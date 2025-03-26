import json
import secrets
from flask import Response, request, url_for, abort
from werkzeug.exceptions import Forbidden, NotFound
from werkzeug.routing import BaseConverter

from sensorhub.constants import *
from sensorhub.models import *
import secrets
def page_key(*args, **kwargs):
    start = request.args.get("start", 0)
    return request.path + f"[start_{start}]"
    
def require_admin(func):
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("Sensorhub-Api-Key") or request.headers.get("apikey", "")
        
        if not api_key:
            print("API key not provided")
            abort(403)

        api_key = api_key.strip()
        key_hash = ApiKey.key_hash(api_key)
        
        db_key = ApiKey.query.filter_by(admin=True).first()
        if db_key is None:
            print("No admin key found in database")
            abort(403)
        
        if not secrets.compare_digest(key_hash, db_key.key):
            print("API key does not match")
            abort(403)

        return func(*args, **kwargs)
    
    return wrapper



def require_sensor_key(func):
    def wrapper(self, sensor, *args, **kwargs):
        api_key = request.headers.get("Sensorhub-Api-Key") or request.headers.get("apikey", "")
        
        if not api_key:
            abort(403)  # No API key provided
            
        api_key = api_key.strip()
        key_hash = ApiKey.key_hash(api_key)
        
        db_key = ApiKey.query.filter_by(sensor=sensor).first()
        if db_key is not None and secrets.compare_digest(key_hash, db_key.key):
            return func(self, sensor, *args, **kwargs)
        
        abort(403)  # Invalid API key
    
    return wrapper


class SensorConverter(BaseConverter):
    
    def to_python(self, sensor_name):
        db_sensor = Sensor.query.filter_by(name=sensor_name).first()
        if db_sensor is None:
            raise NotFound
        return db_sensor
        
    def to_url(self, db_sensor):
        return db_sensor.name
