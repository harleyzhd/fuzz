"""
Fuzzer modules for different file formats.
"""

from .base_fuzzer import BaseFuzzer
from .plaintext_fuzzer import PlaintextFuzzer
from .json_fuzzer import JsonFuzzer
from .xml_fuzzer import XmlFuzzer
from .csv_fuzzer import CsvFuzzer
from .jpeg_fuzzer import JpegFuzzer
from .elf_fuzzer import ElfFuzzer
from .pdf_fuzzer import PdfFuzzer
from .onnx_fuzzer import OnnxFuzzer

__all__ = [
    'BaseFuzzer',
    'PlaintextFuzzer',
    'JsonFuzzer',
    'XmlFuzzer',
    'CsvFuzzer',
    'JpegFuzzer',
    'ElfFuzzer',
    'PdfFuzzer',
    'OnnxFuzzer',
]
