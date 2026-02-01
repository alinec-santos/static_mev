from .detector import GenericSlippageDetector

def make_plugin():
    detectors = [GenericSlippageDetector]
    printers = []
    return detectors, printers
