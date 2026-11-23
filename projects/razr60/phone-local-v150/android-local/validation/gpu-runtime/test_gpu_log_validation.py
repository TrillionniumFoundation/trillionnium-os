import unittest
import gpu_log_validation as gpu


SELECT = "[ INFO] Using 1 device(s): GPUOpenCL"
DEVICE = "llama_prepare_model_devices: using device GPUOpenCL (QUALCOMM Adreno(TM) 830) (unknown id) - 6564 MiB free"
OFFLOAD = "load_tensors: offloaded 43/43 layers to GPU"
BUFFER = "load_tensors:       OpenCL model buffer size =  1340.79 MiB"


class GpuEvidenceTests(unittest.TestCase):
    def verdict(self, *lines):
        return gpu.accelerator_log_evidence("\n".join(lines))["accelerator_offload_observed"]

    def test_actual_backend_with_buffer_alias(self):
        self.assertTrue(self.verdict(SELECT, DEVICE, OFFLOAD, "\x1b[34m" + BUFFER + "\x1b[0m"))

    def test_explicit_device_buffer_label_still_works(self):
        self.assertTrue(self.verdict(SELECT, DEVICE, OFFLOAD, BUFFER.replace("OpenCL", "GPUOpenCL")))

    def test_enumeration_does_not_prove_selection(self):
        self.assertFalse(self.verdict("Found device: GPUOpenCL", DEVICE, OFFLOAD, BUFFER))

    def test_no_prepared_model_device_is_not_sufficient(self):
        self.assertFalse(self.verdict(SELECT, OFFLOAD, BUFFER))

    def test_zero_allocation_and_kv_only_rejected(self):
        self.assertFalse(self.verdict(SELECT, DEVICE, OFFLOAD, BUFFER.replace("1340.79", "0.00")))
        self.assertFalse(self.verdict(SELECT, DEVICE, OFFLOAD, "llama_kv_cache: OpenCL KV buffer size = 336.00 MiB"))

    def test_generic_gpu_and_wrong_backend_buffers_rejected(self):
        for label in ("GPU", "CPU", "HTP0", "NotOpenCL"):
            with self.subTest(label=label):
                self.assertFalse(self.verdict(SELECT, DEVICE, OFFLOAD, BUFFER.replace("OpenCL", label)))

    def test_zero_offload_rejected(self):
        self.assertFalse(self.verdict(SELECT, DEVICE, OFFLOAD.replace("43/43", "0/43"), BUFFER))

    def test_conflicting_selected_backend_rejected(self):
        self.assertFalse(self.verdict(SELECT, "Using 1 device(s): HTP0", DEVICE, OFFLOAD, BUFFER))

    def test_enumerated_unused_backend_warning_retained_without_false_rejection(self):
        result = gpu.accelerator_log_evidence("\n".join((SELECT, DEVICE, OFFLOAD, BUFFER,
            "[ WARN] ggml-hex: failed to query HTP version (err 114) defaulting to v73")))
        self.assertTrue(result["accelerator_offload_observed"])
        self.assertEqual(len(result["warning_lines"]), 1)
        self.assertFalse(result["full_operator_coverage_proven"])


if __name__ == "__main__":
    unittest.main()
