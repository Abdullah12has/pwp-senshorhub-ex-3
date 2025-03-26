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
        # Get the API key from the request headers (check both possible header names)
        api_key = request.headers.get("Sensorhub-Api-Key") or request.headers.get("apikey", "")
        
        if not api_key:
            abort(403)  # No API key provided
            
        api_key = api_key.strip()
        
        # Hash the provided API key
        key_hash = ApiKey.key_hash(api_key)
        
        # Find the admin key in the database
        db_key = ApiKey.query.filter_by(admin=True).first()
        
        # Check if no admin key exists or the keys don't match
        if not db_key or not secrets.compare_digest(key_hash, db_key.key):
            # Explicitly raise a Forbidden exception
            # This ensures a 403 status code is returned
            abort(403)
        
        # If authentication succeeds, call the original function
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
