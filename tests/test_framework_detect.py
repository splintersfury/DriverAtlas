"""Unit tests for framework detection with synthetic import dicts."""

import os
import pytest

from driveratlas.framework_detect import FrameworkClassifier, FrameworkMatch

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRAMEWORKS_PATH = os.path.join(_REPO_ROOT, "signatures", "frameworks.yaml")


@pytest.fixture
def classifier():
    return FrameworkClassifier(_FRAMEWORKS_PATH)


class TestPureMinifilter:
    def test_minifilter_detection(self, classifier):
        imports = {
            "fltmgr.sys": [
                "FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter",
                "FltGetStreamContext", "FltAllocateContext", "FltReleaseContext",
            ],
            "ntoskrnl.exe": ["ExAllocatePoolWithTag", "ExFreePoolWithTag"],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "minifilter"
        assert primary.confidence >= 0.3
        assert "FltRegisterFilter" in primary.matched_symbols

    def test_minifilter_high_confidence(self, classifier):
        """Full set of minifilter imports should give high confidence."""
        imports = {
            "fltmgr.sys": [
                "FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter",
                "FltGetStreamContext", "FltGetStreamHandleContext",
                "FltGetInstanceContext", "FltGetVolumeContext",
                "FltReleaseContext", "FltAllocateContext",
                "FltSetStreamContext", "FltSetStreamHandleContext",
                "FltCreateCommunicationPort", "FltSendMessage",
                "FltGetFileNameInformation", "FltReleaseFileNameInformation",
            ],
            "ntoskrnl.exe": ["ExAllocatePoolWithTag"],
        }
        primary, _ = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "minifilter"
        assert primary.confidence > 0.6


class TestPureNdisMiniport:
    def test_ndis_miniport_detection(self, classifier):
        imports = {
            "ndis.sys": [
                "NdisMRegisterMiniportDriver", "NdisMDeregisterMiniportDriver",
                "NdisMSetMiniportAttributes", "NdisMIndicateReceiveNetBufferLists",
            ],
            "ntoskrnl.exe": ["ExAllocatePoolWithTag"],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "ndis_miniport"
        assert primary.confidence >= 0.3


class TestWfpCallout:
    def test_wfp_detection(self, classifier):
        imports = {
            "fwpkclnt.sys": [
                "FwpsCalloutRegister1", "FwpmFilterAdd0",
                "FwpmSubLayerAdd0", "FwpmEngineOpen0", "FwpmEngineClose0",
            ],
            "ntoskrnl.exe": ["IoCreateDevice", "ExAllocatePoolWithTag"],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "wfp_callout"


class TestKmdf:
    def test_kmdf_detection(self, classifier):
        imports = {
            "wdfldr.sys": ["WdfVersionBind", "WdfVersionUnbind"],
            "ntoskrnl.exe": [
                "WdfDriverCreate", "WdfDeviceCreate",
                "WdfRequestComplete", "ExAllocatePoolWithTag",
            ],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "kmdf"


class TestWdmRawFallback:
    def test_wdm_raw_only_when_no_framework(self, classifier):
        """wdm_raw should only match if no other framework hits threshold."""
        imports = {
            "ntoskrnl.exe": [
                "IoCreateDevice", "IoDeleteDevice",
                "IoCreateSymbolicLink", "IofCompleteRequest",
                "ExAllocatePoolWithTag",
            ],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "wdm_raw"

    def test_wdm_raw_not_when_minifilter_present(self, classifier):
        """wdm_raw should not be primary when a real framework matches."""
        imports = {
            "fltmgr.sys": [
                "FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter",
            ],
            "ntoskrnl.exe": [
                "IoCreateDevice", "IoDeleteDevice", "ExAllocatePoolWithTag",
            ],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "minifilter"


class TestMultiFramework:
    def test_wfp_plus_wdm_secondary(self, classifier):
        """A WFP driver with IoCreateDevice should show wdm_raw as secondary."""
        imports = {
            "fwpkclnt.sys": [
                "FwpsCalloutRegister1", "FwpmFilterAdd0",
                "FwpmSubLayerAdd0", "FwpmEngineOpen0",
            ],
            "ntoskrnl.exe": [
                "IoCreateDevice", "IoDeleteDevice",
                "IoCreateSymbolicLink", "IofCompleteRequest",
                "ExAllocatePoolWithTag",
            ],
        }
        primary, secondary = classifier.classify(imports)
        assert primary is not None
        assert primary.name == "wfp_callout"
        sec_names = [s.name for s in secondary]
        assert "wdm_raw" in sec_names


class TestEdgeCases:
    def test_empty_imports(self, classifier):
        primary, secondary = classifier.classify({})
        assert primary is None
        assert secondary == []

    def test_unknown_dlls_only(self, classifier):
        imports = {"somevendor.dll": ["CustomFunc1", "CustomFunc2"]}
        primary, secondary = classifier.classify(imports)
        assert primary is None

    def test_framework_match_dataclass(self):
        m = FrameworkMatch(name="test", score=5.0, confidence=0.8, matched_symbols=["FuncA"])
        assert m.name == "test"
        assert m.confidence == 0.8
