import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "compare_attachment_inventory", Path(__file__).resolve().parents[2] / "scripts" /
    "compare_attachment_inventory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def ours(scope, nid="0x0000000000002085", size=42):
    return f"ATT\t0x2004\t0x2085\t{size}\t1\t1\t{scope} attachment {nid}\n"


class ScopedComparisonTest(unittest.TestCase):
    a = "message 0x0000000000002004"
    b = a + " attachment 0x0000000000002085 embedded 0x0000000000002004"

    def oracle(self):
        return (f"SCOPE\t{self.a}\t1\nSCOPE\t{self.b}\t1\n"
                f"ROW\t{self.a} attachment 0x0000000000002085\t42\n"
                f"ROW\t{self.b} attachment 0x0000000000002085\t42\nCOMPLETE\n")

    def test_same_local_ids_different_ancestry(self):
        self.assertIn("matched=2", module.compare(ours(self.a) + ours(self.b), self.oracle()))

    def test_missing_row_cannot_match_twice(self):
        with self.assertRaises(ValueError):
            module.compare(ours(self.a), self.oracle())

    def test_duplicate_ours_or_oracle(self):
        both = ours(self.a) + ours(self.b)
        with self.assertRaises(ValueError):
            module.compare(both + ours(self.a), self.oracle())
        with self.assertRaises(ValueError):
            module.compare(both, self.oracle().replace("COMPLETE", f"ROW\t{self.a} attachment "
                           "0x0000000000002085\t42\nCOMPLETE"))

    def test_extra_row_inside_compared_scope(self):
        with self.assertRaises(ValueError):
            module.compare(ours(self.a) + ours(self.b) + ours(self.a, "0x3005"), self.oracle())

    def test_truncated_oracle_and_wrong_size(self):
        both = ours(self.a) + ours(self.b)
        with self.assertRaises(ValueError):
            module.compare(both, self.oracle().replace("COMPLETE\n", ""))
        with self.assertRaises(ValueError):
            module.compare(ours(self.a, size=43) + ours(self.b), self.oracle())
        with self.assertRaises(ValueError):
            module.compare(both, self.oracle().replace(f"ROW\t{self.b} attachment "
                           "0x0000000000002085\t42\n", ""))


if __name__ == "__main__":
    unittest.main()
