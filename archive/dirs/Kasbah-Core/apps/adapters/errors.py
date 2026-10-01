class AdapterError(Exception):
    pass

class AdapterNotFound(AdapterError):
    pass

class AdapterLoadError(AdapterError):
    pass
