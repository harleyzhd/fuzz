import random
from typing import Optional

import onnx
from onnx import helper, numpy_helper
import numpy as np

from .base_fuzzer import BaseFuzzer


class OnnxFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        try:
            self.model = onnx.load_model_from_string(example_input)
            self.model_bytes = self.model.SerializeToString()
        except Exception:
            self.model = None
            self.model_bytes = None
        self._garbage_prob = 0.08

    def _maybe_clone_model(self) -> Optional[onnx.ModelProto]:
        if self.model_bytes is None:
            try:
                m = onnx.ModelProto()
                m.ParseFromString(self.example_input)
                return m
            except Exception:
                return None
        clone = onnx.ModelProto()
        try:
            clone.ParseFromString(self.model_bytes)
            return clone
        except Exception:
            return None

    def _serialize(self, model: Optional[onnx.ModelProto]) -> bytes:
        if model is None:
            return self.mutate_bytes(self.example_input)
        return model.SerializeToString()

    def _add_random_node(self, model: onnx.ModelProto):
        nodes = list(model.graph.node)
        if len(nodes) < 1 or len(model.graph.input) < 1:
            return model
        input_name = random.choice(model.graph.input).name
        output_name = f"fuzz_out_{random.randint(0, 1<<16)}"
        node = helper.make_node(
            random.choice(["Relu", "Sigmoid", "Tanh", "Exp"]),
            inputs=[input_name],
            outputs=[output_name],
            name=f"Fuzzer_{random.randint(0, 1<<16)}",
        )
        model.graph.node.append(node)
        model.graph.output.extend([helper.make_tensor_value_info(output_name, onnx.TensorProto.FLOAT, None)])
        return model

    def _mutate_tensor(self, model: onnx.ModelProto):
        tensors = list(model.graph.initializer)
        if not tensors:
            return model
        tensor = random.choice(tensors)
        array = numpy_helper.to_array(tensor)
        if array.size == 0:
            return model
        idx = random.randrange(array.size)
        flat = array.flatten()
        flat[idx] = random.uniform(-1e6, 1e6)
        new_array = flat.reshape(array.shape)
        new_tensor = numpy_helper.from_array(new_array, name=tensor.name)
        tensors = [t if t.name != tensor.name else new_tensor for t in tensors]
        model.graph.initializer.clear()
        model.graph.initializer.extend(tensors)
        return model

    def _random_input_shape(self, model: onnx.ModelProto):
        if not model.graph.input:
            return model
        target = random.choice(model.graph.input)
        dims = []
        for dim in target.type.tensor_type.shape.dim:
            if dim.HasField("dim_value"):
                dim.dim_value = max(1, int(dim.dim_value) + random.randint(-5, 5))
            else:
                dim.dim_value = random.randint(1, 64)
            dims.append(dim)
        return model

    def _corrupt_opset(self, model: onnx.ModelProto):
        if model.opset_import:
            entry = random.choice(model.opset_import)
            entry.version = max(0, entry.version + random.randint(-30, 30))
        else:
            imp = onnx.helper.make_opsetid("", random.randint(0, 20))
            model.opset_import.extend([imp])
        return model

    def _drop_initializer(self, model: onnx.ModelProto):
        if not model.graph.initializer or not model.graph.node:
            return model
        victim = random.choice(model.graph.initializer)
        model.graph.initializer.remove(victim)
        # leave nodes still referencing removed tensor to trigger validation failure
        return model

    def _invalid_tensor_shape(self, model: onnx.ModelProto):
        if not model.graph.initializer:
            return model
        tensor = random.choice(model.graph.initializer)
        tensor.ClearField("dims")
        tensor.dims.extend([random.randint(1000, 5000) for _ in range(3)])
        return model

    def _raw_garbage(self) -> bytes:
        size = random.randint(32, 1024)
        return bytes(random.getrandbits(8) for _ in range(size))

    def _shuffle_outputs(self, model: onnx.ModelProto):
        outs = list(model.graph.output)
        if len(outs) > 1:
            random.shuffle(outs)
            model.graph.output.clear()
            model.graph.output.extend(outs)
        if outs:
            chosen = random.choice(outs)
            chosen.name = f"fuzz_out_{random.randint(0,1<<16)}"
        return model

    def _corrupt_attribute(self, model: onnx.ModelProto):
        if not model.graph.node:
            return model
        node = random.choice(model.graph.node)
        if not node.attribute:
            node.attribute.extend([helper.make_attribute("fuzz_attr", random.random())])
            return model
        attr = random.choice(node.attribute)
        attr.ClearField("f")
        attr.ClearField("i")
        attr.ClearField("s")
        attr.ClearField("floats")
        attr.ClearField("ints")
        attr.ClearField("strings")
        pick = random.choice(["f", "i", "s"])
        if pick == "f":
            attr.f = random.uniform(-1e9, 1e9)
        elif pick == "i":
            attr.i = random.randint(-1 << 30, 1 << 30)
        else:
            attr.s = os.urandom(random.randint(1, 8))
        return model

    def _mix_opset(self, model: onnx.ModelProto):
        # add a second opset import with extreme version or empty domain
        model.ir_version = random.choice([0, 1, 3, 7, 10, onnx.IR_VERSION, onnx.IR_VERSION + random.randint(1, 10)])
        if model.opset_import:
            choice_imp = random.choice(model.opset_import)
            choice_imp.version = max(0, choice_imp.version + random.randint(-20, 40))
        model.opset_import.extend([helper.make_opsetid("", random.randint(0, 30))])
        return model

    def _unknown_custom_node(self, model: onnx.ModelProto):
        inp = [i.name for i in model.graph.input]
        use_in = random.sample(inp, k=min(len(inp), random.randint(0, max(1, len(inp)))))
        out_name = f"unk_out_{random.randint(0, 1<<16)}"
        node = helper.make_node(
            f"UnknownOp{random.randint(0, 100)}",
            inputs=use_in,
            outputs=[out_name],
            domain="org.example.fuzz",
            name=f"fuzz_custom_{random.randint(0,1<<16)}",
        )
        model.graph.node.append(node)
        model.graph.output.extend([helper.make_tensor_value_info(out_name, onnx.TensorProto.FLOAT, None)])
        return model

    def _shape_mismatch_initializer(self, model: onnx.ModelProto):
        if not model.graph.initializer:
            return model
        t = random.choice(model.graph.initializer)
        raw = t.raw_data if t.raw_data else t.SerializePartialToString()
        t.ClearField("dims")
        t.raw_data = raw + os.urandom(random.randint(1, 32))
        t.dims.extend([random.randint(1024, 4096) for _ in range(4)])
        return model

    def _broken_subgraph(self, model: onnx.ModelProto):
        control_ops = [n for n in model.graph.node if n.op_type in ("If", "Loop", "Scan")]
        if not control_ops:
            return model
        node = random.choice(control_ops)
        node.ClearField("attribute")
        node.attribute.extend([helper.make_attribute("body", None)])
        return model

    def _external_data_hint(self, model: onnx.ModelProto):
        if not model.graph.initializer:
            return model
        init = random.choice(model.graph.initializer)
        init.ClearField("data_location")
        init.data_location = onnx.TensorProto.EXTERNAL
        init.external_data.clear()
        init.external_data.extend([helper.StringStringEntryProto(key="location", value="/tmp/fuzz_missing.bin")])
        return model

    def generate(self):
        if random.random() < self._garbage_prob:
            yield self._raw_garbage()
        base = self._maybe_clone_model()
        if base:
            yield base.SerializeToString()
        for strategy in (
            self._add_random_node,
            self._mutate_tensor,
            self._random_input_shape,
            self._corrupt_opset,
            self._drop_initializer,
            self._invalid_tensor_shape,
            self._shuffle_outputs,
            self._corrupt_attribute,
            self._mix_opset,
            self._unknown_custom_node,
            self._shape_mismatch_initializer,
            self._broken_subgraph,
            self._external_data_hint,
        ):
            model = self._maybe_clone_model()
            if model:
                mutated = strategy(model)
                yield self._serialize(mutated)
        if random.random() < self._garbage_prob:
            yield self._raw_garbage()

        while True:
            model = self._maybe_clone_model()
            if model is None:
                if random.random() < self._garbage_prob:
                    yield self._raw_garbage()
                else:
                    yield self.mutate_bytes(self.example_input)
                continue
            choice = random.choice([
                self._add_random_node,
                self._mutate_tensor,
                self._random_input_shape,
                self._corrupt_opset,
                self._drop_initializer,
                self._invalid_tensor_shape,
                self._raw_garbage,
                self._shuffle_outputs,
                self._corrupt_attribute,
                self._mix_opset,
                self._unknown_custom_node,
                self._shape_mismatch_initializer,
                self._broken_subgraph,
                self._external_data_hint,
            ])
            try:
                if choice is self._raw_garbage:
                    if random.random() < self._garbage_prob:
                        yield self._raw_garbage()
                    else:
                        continue
                else:
                    mutated = choice(model)
                    yield self._serialize(mutated)
            except Exception:
                yield self.mutate_bytes(self.example_input)
