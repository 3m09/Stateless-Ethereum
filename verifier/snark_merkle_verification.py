import subprocess
import os
from registry.verifiers import BaseVerifier, register_verifier

@register_verifier("zksnarkmerkle")
class SnarkMerkleProofVerifier(BaseVerifier):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def verify_proof(self, values, keys, root, proof, setup=None) -> bool:
        env = os.environ.copy()
        env["PYSNARK_BACKEND"] = "zkifbellman"

        def run_and_check(cmd, expected_substrings, shell=False, env=None):
            result = subprocess.run(
                cmd,
                shell=shell,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            output = result.stdout + result.stderr

            for expected in expected_substrings:
                if expected not in output:
                    raise RuntimeError(
                        f"Command failed validation:\n"
                        f"Command: {cmd}\n"
                        f"Missing: '{expected}'\n"
                        f"Output:\n{output}"
                    )

            return output

        run_and_check(
            "cat circuit.zkif | zkif_bellman setup",
            expected_substrings=[
                "Written parameters into",
            ],
            shell=True,
        )

        run_and_check(
            "cat computation.zkif | zkif_bellman prove",
            expected_substrings=[
                "Reading parameters from",
                "Written proof into",
            ],
            shell=True,
        )

        verify_output = run_and_check(
            "cat circuit.zkif | zkif_bellman verify",
            expected_substrings=[
                "Reading parameters from",
                "Reading proof from",
            ],
            shell=True,
        )

        # Final success condition
        return "The proof is valid" in verify_output
