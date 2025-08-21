import requests
from decimal import Decimal
from django.conf import settings
import time
import logging

logger = logging.getLogger(__name__)

class OpenRouteService:
    def __init__(self):
        # API Key gratuita de OpenRouteService
        self.api_key = getattr(settings, 'OPENROUTE_API_KEY', '5b3ce3597851110001cf6248YOUR_API_KEY_HERE')
        self.COSTO_BASE = Decimal('40.00')  # ✨ CAMBIO: De 50.00 a 40.00
        self.ALCANCE_GRATIS_KM = Decimal('4.0')
        self.COSTO_POR_KM_EXTRA = Decimal('10.00')
        self.max_retries = 2  # Reducido para ser más rápido
        self.timeout = 10     # Reducido timeout
    
    def clean_address(self, address):
        """Limpia y normaliza la dirección para mejor geocoding - VERSION SIMPLE"""
        if not address:
            return ""
        
        # Solo limpiezas básicas
        cleaned = address.strip()
        
        # Reemplazos mínimos
        replacements = {
            'av.': 'avenida',
            'blvd.': 'boulevard',
            'col.': 'colonia',
            'fracc.': 'fraccionamiento',
            '#': 'numero',
            'no.': 'numero',
        }
        
        cleaned_lower = cleaned.lower()
        for old, new in replacements.items():
            cleaned_lower = cleaned_lower.replace(old, new)
        
        # Capitalizar primera letra de cada palabra
        return ' '.join(word.capitalize() for word in cleaned_lower.split())
    
    def get_coordinates(self, address, city="Puerto Vallarta, Jalisco"):
        """Obtener coordenadas con estrategia simplificada"""
        if not address or not address.strip():
            logger.error("Dirección vacía proporcionada")
            return None, None
        
        # Limpiar dirección de forma simple
        clean_addr = self.clean_address(address)
        
        # Solo 3 estrategias principales
        search_strategies = [
            f"{clean_addr}, {city}, México",
            f"{address}, Puerto Vallarta, Jalisco, México",  # Original
            f"{address}, México"  # Más simple
        ]
        
        for i, search_address in enumerate(search_strategies):
            logger.info(f"🔍 Estrategia {i+1}: Buscando '{search_address}'")
            
            lat, lng = self._geocode_single_address(search_address)
            
            if lat and lng:
                # Validación MUY permisiva para México
                if self._validate_coordinates_simple(lat, lng):
                    logger.info(f"✅ Coordenadas encontradas: {lat}, {lng}")
                    return lat, lng
                else:
                    logger.warning(f"⚠️ Coordenadas fuera de México: {lat}, {lng}")
                    continue
            
            # Pausa mínima entre intentos
            time.sleep(0.3)
        
        logger.error(f"❌ No se pudieron obtener coordenadas para: {address}")
        return None, None
    
    def _geocode_single_address(self, address):
        """Geocodificar una dirección específica - SIMPLIFICADO"""
        url = "https://api.openrouteservice.org/geocode/search"
        params = {
            'api_key': self.api_key,
            'text': address,
            'boundary.country': 'MX',
            'focus.point.lat': 20.6534,  # Centro de Puerto Vallarta
            'focus.point.lon': -105.2253,
            'size': 1,  # Solo el mejor resultado
        }
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"🌐 Geocoding intento {attempt + 1}: {address}")
                response = requests.get(url, params=params, timeout=self.timeout)
                
                if response.status_code == 429:  # Rate limit
                    wait_time = 1 + attempt  # Espera simple
                    logger.warning(f"⏳ Rate limit, esperando {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                if response.status_code != 200:
                    logger.error(f"❌ Error HTTP {response.status_code}")
                    continue
                
                data = response.json()
                
                if data.get('features'):
                    # Tomar el primer resultado sin muchas validaciones
                    feature = data['features'][0]
                    coordinates = feature['geometry']['coordinates']
                    lng, lat = coordinates[0], coordinates[1]
                    logger.info(f"📍 Resultado: {lat}, {lng}")
                    return lat, lng
                
                logger.warning(f"⚠️ Sin resultados para: {address}")
                return None, None
                
            except requests.exceptions.Timeout:
                logger.warning(f"⏰ Timeout en intento {attempt + 1}")
                continue
            except Exception as e:
                logger.error(f"💥 Error: {e}")
                continue
        
        return None, None
    
    def _validate_coordinates_simple(self, lat, lng):
        """Validación MUY permisiva - solo verifica que esté en México"""
        # Límites muy amplios de México
        mexico_bounds = {
            'lat_min': 14.0, 'lat_max': 33.0,
            'lng_min': -119.0, 'lng_max': -86.0
        }
        
        lat, lng = float(lat), float(lng)
        
        return (mexico_bounds['lat_min'] <= lat <= mexico_bounds['lat_max'] and 
                mexico_bounds['lng_min'] <= lng <= mexico_bounds['lng_max'])
    
    def calcular_distancia(self, origen_lat, origen_lng, destino_lat, destino_lng):
        """Calcular distancia - PRIORIZA RESULTADO RÁPIDO"""
        
        # Validar coordenadas de entrada
        try:
            origen_lat, origen_lng = float(origen_lat), float(origen_lng)
            destino_lat, destino_lng = float(destino_lat), float(destino_lng)
        except (ValueError, TypeError):
            logger.error("❌ Coordenadas inválidas")
            return None
        
        if not all([origen_lat, origen_lng, destino_lat, destino_lng]):
            logger.error("❌ Coordenadas faltantes")
            return None
        
        # Calcular distancia haversine como referencia
        haversine_distance = self._calculate_haversine_distance(
            origen_lat, origen_lng, destino_lat, destino_lng
        )
        
        logger.info(f"📏 Distancia Haversine: {haversine_distance:.2f} km")
        
        # Intentar OpenRouteService solo una vez
        ors_distance = self._calculate_ors_distance_simple(origen_lat, origen_lng, destino_lat, destino_lng)
        
        if ors_distance and ors_distance > 0:
            # Validación más permisiva: solo rechazar si es extremadamente diferente
            if ors_distance <= haversine_distance * 3.0:  # Hasta 300% de diferencia
                logger.info(f"✅ Usando distancia ORS: {ors_distance:.2f} km")
                return ors_distance
            else:
                logger.warning(f"⚠️ Distancia ORS muy diferente ({ors_distance:.2f} vs {haversine_distance:.2f})")
        
        # Usar haversine como fallback confiable
        logger.info(f"🔄 Usando distancia Haversine: {haversine_distance:.2f} km")
        return haversine_distance
    
    def _calculate_ors_distance_simple(self, origen_lat, origen_lng, destino_lat, destino_lng):
        """Calcular distancia ORS - UN SOLO INTENTO"""
        url = "https://api.openrouteservice.org/v2/matrix/driving-car"
        
        headers = {
            'Authorization': self.api_key,
            'Content-Type': 'application/json'
        }
        
        body = {
            "locations": [
                [float(origen_lng), float(origen_lat)],
                [float(destino_lng), float(destino_lat)]
            ],
            "metrics": ["distance"],
            "units": "km"
        }
        
        try:
            logger.info("🛣️ Calculando distancia ORS...")
            response = requests.post(url, headers=headers, json=body, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'distances' in data and data['distances']:
                    distance_km = data['distances'][0][1]
                    if distance_km and distance_km > 0:
                        logger.info(f"✅ Distancia ORS: {distance_km} km")
                        return distance_km
            else:
                logger.warning(f"⚠️ ORS HTTP {response.status_code}")
                
        except Exception as e:
            logger.warning(f"⚠️ Error ORS: {e}")
        
        return None
    
    def _calculate_haversine_distance(self, lat1, lon1, lat2, lon2):
        """Calcula la distancia haversine entre dos puntos en km"""
        import math
        
        # Convertir grados a radianes
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        
        # Diferencias
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        # Fórmula haversine
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        # Radio de la Tierra en km
        r = 6371
        
        return c * r
    
    def calcular_costo_envio(self, distancia_km):
        """Calcular costo de envío - LÍMITES MÁS RAZONABLES"""
        if not distancia_km or distancia_km <= 0:
            logger.warning("⚠️ Distancia inválida, usando costo base")
            return self.COSTO_BASE
        
        logger.info(f"💰 Calculando costo para {distancia_km:.2f} km")
        
        if distancia_km <= self.ALCANCE_GRATIS_KM:
            costo = self.COSTO_BASE
        else:
            km_extra = Decimal(str(distancia_km)) - self.ALCANCE_GRATIS_KM
            costo_extra = km_extra * self.COSTO_POR_KM_EXTRA
            costo = self.COSTO_BASE + costo_extra
        
        # Límite más razonable: máximo $150 en lugar de $200
        if costo > 150:
            logger.warning(f"⚠️ Costo muy alto ({costo}), limitando a $150")
            costo = Decimal('150.00')
        
        logger.info(f"💰 Costo final: ${costo}")
        return costo


# Mantener la clase original para compatibilidad
class GoogleMapsService:
    """Clase de compatibilidad - ahora usa OpenRouteService balanceado"""
    def __init__(self):
        self.service = OpenRouteService()
    
    def get_coordinates(self, address):
        return self.service.get_coordinates(address)
    
    def calcular_distancia(self, origen_lat, origen_lng, destino_lat, destino_lng):
        return self.service.calcular_distancia(origen_lat, origen_lng, destino_lat, destino_lng)
    
    def calcular_costo_envio(self, distancia_km):
        return self.service.calcular_costo_envio(distancia_km)