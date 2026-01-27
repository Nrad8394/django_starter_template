"""Core services module"""

# Local service modules
from .profile_completion import ProfileCompletionService

# Import service classes from the services.py module in parent directory
# We need to handle the naming conflict: both services/ (package) and services.py (module) exist
import sys
import os

# Get the path to the services.py module
services_py_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'services.py')

# Load services.py as a separate module to avoid name collision
if os.path.exists(services_py_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('core_services_module', services_py_path)
    if spec and spec.loader:
        _services_module = importlib.util.module_from_spec(spec)
        # Import before executing to handle dependencies
        sys.modules['core_services_module'] = _services_module
        try:
            spec.loader.exec_module(_services_module)
            # Export the service classes
            TwoFactorAuthService = _services_module.TwoFactorAuthService
            DeviceDetectionService = _services_module.DeviceDetectionService
            GeoIPService = _services_module.GeoIPService
            AuthenticationService = _services_module.AuthenticationService
        except Exception as e:
            # Services might not be available during initial setup
            TwoFactorAuthService = None
            DeviceDetectionService = None
            GeoIPService = None
            AuthenticationService = None

__all__ = [
    'ProfileCompletionService',
    'TwoFactorAuthService',
    'DeviceDetectionService',
    'GeoIPService',
    'AuthenticationService',
]
