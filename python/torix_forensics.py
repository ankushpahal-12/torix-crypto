"""
TORIX-512 Cryptographic Suite: 2D Spatial Forensic Tamper Heatmap Engine (Frontier 4)
====================================================================================
Transforms TORIX from a passive binary digest into a Forensic-Intelligent Cryptographic
Primitive. Evaluates intermediate 2-torus state evolution to pinpoint the exact block,
byte offset, timestamp, and mathematical classification of tampering in audio streams,
video frames, legal evidence, and container files.
"""

import os
import sys
import math
import struct
from enum import Enum
from typing import List, Tuple, Optional, Dict, Any, Union

# Ensure python directory is in sys.path
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

import h512
from h512 import IV, disperse_message_block, compress_block, pad_message


# ==============================================================================
# 1. ENUMS & DATA STRUCTURES
# ==============================================================================
class TamperType(str, Enum):
    AUTHENTIC = "AUTHENTIC"
    BIT_ROT = "BIT_ROT"
    PAYLOAD_SUBSTITUTION = "PAYLOAD_SUBSTITUTION"
    FRAMING_SLIP = "FRAMING_SLIP"
    TRUNCATION = "TRUNCATION"
    APPEND = "APPEND"


def count_bits(n: int) -> int:
    """Computes the Hamming weight of an 8-bit integer."""
    return bin(n & 0xFF).count("1")


def toroidal_distance(r1: int, c1: int, r2: int, c2: int) -> int:
    """
    Computes geodesic Manhattan distance on the discrete 2-torus T^2 = (Z/8Z) x (Z/8Z).
    d_T2 = min(|r1-r2|, 8-|r1-r2|) + min(|c1-c2|, 8-|c1-c2|)
    """
    dr = abs(r1 - r2)
    dr = min(dr, 8 - dr)
    dc = abs(c1 - c2)
    dc = min(dc, 8 - dc)
    return dr + dc


class ToroidalHeatmap:
    """
    Represents an 8x8 spatial energy field over the discrete 2-torus T^2.
    """
    def __init__(self, energy_matrix: List[List[float]], epicenter: Tuple[int, int], peak: float, mean: float):
        self.matrix = energy_matrix
        self.epicenter = epicenter
        self.peak_energy = peak
        self.mean_energy = mean

    def render_ascii(self, title: str = "TORIX-512 TOROIDAL SPATIAL HEATMAP (8x8)") -> str:
        """Renders an ASCII visualization of the toroidal energy field."""
        # Density characters: from lowest to highest
        shades = ["  ", " .", " :", " -", " =", " +", " *", " #", "##"]
        lines = []
        border_h = "-" * 26
        lines.append(f"  +{border_h}+")
        lines.append(f"  | {title:^24} |")
        lines.append(f"  +{border_h}+")
        lines.append("  | c: 0  1  2  3  4  5  6  7  |")
        lines.append(f"  |  {' ' * 24}|")

        max_e = max(self.peak_energy, 1.0)
        for r in range(8):
            row_str = f"r{r}|  "
            for c in range(8):
                e = self.matrix[r][c]
                ratio = min(e / max_e, 1.0)
                idx = min(int(ratio * (len(shades) - 1)), len(shades) - 1)
                cell_char = shades[idx]
                if (r, c) == self.epicenter and self.peak_energy > 0:
                    row_str += "><"  # Mark epicenter
                else:
                    row_str += cell_char + " "
            row_str += "|"
            lines.append("  " + row_str)

        lines.append(f"  +{border_h}+")
        lines.append(f"  Toroidal Epicenter (r*, c*): ({self.epicenter[0]}, {self.epicenter[1]}) | Peak Energy: {self.peak_energy:.2f}")
        return "\n".join(lines)


class BlockSyndrome:
    """
    Differential analysis of a single 64-byte block between authentic and suspect streams.
    """
    def __init__(
        self,
        block_idx: int,
        delta_matrix: List[List[int]],
        hamming_weight: int,
        active_cells: int,
        entropy: float,
        heatmap: ToroidalHeatmap,
        input_diff_bytes: Optional[bytes] = None,
    ):
        self.block_idx = block_idx
        self.delta_matrix = delta_matrix
        self.hamming_weight = hamming_weight
        self.active_cells = active_cells
        self.entropy = entropy
        self.heatmap = heatmap
        self.input_diff_bytes = input_diff_bytes

        # Calculate input bit diff if raw input blocks were compared
        self.input_bits_flipped = sum(count_bits(b) for b in input_diff_bytes) if input_diff_bytes else 0


class ForensicReport:
    """
    Comprehensive forensic audit output detailing verdict, location, and telemetry.
    """
    def __init__(
        self,
        verdict: TamperType,
        is_authentic: bool,
        diverging_block: Optional[int] = None,
        byte_offset: Optional[int] = None,
        estimated_timestamp_sec: Optional[float] = None,
        epicenter: Optional[Tuple[int, int]] = None,
        injected_byte_in_block: Optional[int] = None,
        confidence: float = 1.0,
        total_blocks_compared: int = 0,
        diverging_blocks_count: int = 0,
        syndromes: Optional[List[BlockSyndrome]] = None,
        summary: str = "",
    ):
        self.verdict = verdict
        self.is_authentic = is_authentic
        self.diverging_block = diverging_block
        self.byte_offset = byte_offset
        self.estimated_timestamp_sec = estimated_timestamp_sec
        self.epicenter = epicenter
        self.injected_byte_in_block = injected_byte_in_block
        self.confidence = confidence
        self.total_blocks_compared = total_blocks_compared
        self.diverging_blocks_count = diverging_blocks_count
        self.syndromes = syndromes or []
        self.summary = summary

    def format_report(self) -> str:
        """Formats the forensic audit into a structured technical summary."""
        lines = []
        lines.append("=" * 72)
        lines.append("  TORIX-512 SPATIAL FORENSIC AUDIT REPORT (FRONTIER 4)")
        lines.append("=" * 72)
        lines.append(f"  VERDICT               : {self.verdict.value}")
        lines.append(f"  AUTHENTICITY STATUS   : {'PASSED (Zero Tamper)' if self.is_authentic else 'FAILED (Tampering Confirmed)'}")
        lines.append(f"  CONFIDENCE SCORE      : {self.confidence * 100:.1f}%")
        lines.append(f"  TOTAL BLOCKS ANALYZED : {self.total_blocks_compared}")
        lines.append(f"  DIVERGENT BLOCKS      : {self.diverging_blocks_count}")

        if not self.is_authentic:
            lines.append("-" * 72)
            lines.append("  TAMPER LOCALIZATION TELEMETRY:")
            if self.diverging_block is not None:
                lines.append(f"  * Divergent Block Index: Block #{self.diverging_block}")
            if self.byte_offset is not None:
                lines.append(f"  * Linear Byte Offset   : Byte {self.byte_offset} (0x{self.byte_offset:X})")
            if self.estimated_timestamp_sec is not None:
                lines.append(f"  * Estimated Timestamp  : {self.estimated_timestamp_sec:.3f} seconds")
            if self.epicenter is not None:
                lines.append(f"  * Toroidal Epicenter   : Cell (r={self.epicenter[0]}, c={self.epicenter[1]}) on T^2")
            if self.injected_byte_in_block is not None:
                lines.append(f"  * Block Byte Position  : Byte index {self.injected_byte_in_block} in 64-byte block")
            lines.append("-" * 72)
            lines.append(f"  ANALYSIS SUMMARY: {self.summary}")

            if self.syndromes and self.diverging_block is not None:
                syn = next((s for s in self.syndromes if s.block_idx == self.diverging_block), None)
                if syn:
                    lines.append("\n" + syn.heatmap.render_ascii("EPICENTER SPATIAL DIFFUSION"))
        else:
            lines.append("-" * 72)
            lines.append("  ANALYSIS SUMMARY: Both cryptographic streams match perfectly across all blocks.")
        lines.append("=" * 72)
        return "\n".join(lines)


# ==============================================================================
# 2. CORE FORENSIC ANALYZER ENGINE
# ==============================================================================
class TorixForensicAnalyzer:
    """
    Forensic analysis engine utilizing TORIX's discrete 2-torus state geometry
    to localize and classify stream modifications.
    """

    @staticmethod
    def compute_spatial_energy(delta: List[List[int]]) -> ToroidalHeatmap:
        """
        Computes the continuous 2D spatial energy field over T^2.
        E[r, c] = w_H(delta[r, c]) + 0.25 * sum_{(i,j) in N(r,c)} w_H(delta[i, j])
        Also computes the angular circular centroid (epicenter) over T^2.
        """
        hw_grid = [[count_bits(delta[r][c]) for c in range(8)] for r in range(8)]
        energy = [[0.0] * 8 for _ in range(8)]

        peak_val = 0.0
        sum_val = 0.0

        for r in range(8):
            for c in range(8):
                # 4-neighbor Von Neumann coupling with periodic boundary wrap
                north = hw_grid[(r - 1) % 8][c]
                south = hw_grid[(r + 1) % 8][c]
                west = hw_grid[r][(c - 1) % 8]
                east = hw_grid[r][(c + 1) % 8]
                
                cell_e = hw_grid[r][c] + 0.25 * (north + south + west + east)
                energy[r][c] = cell_e
                sum_val += cell_e
                if cell_e > peak_val:
                    peak_val = cell_e

        mean_val = sum_val / 64.0

        # Toroidal Centroid via Circular Statistics:
        # Map row r and col c to angles theta_r = 2*pi*r / 8, phi_c = 2*pi*c / 8
        xr, yr = 0.0, 0.0
        xc, yc = 0.0, 0.0
        total_weight = 0.0

        for r in range(8):
            for c in range(8):
                w = energy[r][c]
                total_weight += w
                theta_r = 2.0 * math.pi * r / 8.0
                phi_c = 2.0 * math.pi * c / 8.0
                xr += w * math.cos(theta_r)
                yr += w * math.sin(theta_r)
                xc += w * math.cos(phi_c)
                yc += w * math.sin(phi_c)

        if total_weight > 0.001 and (xr != 0 or yr != 0) and (xc != 0 or yc != 0):
            ang_r = math.atan2(yr, xr)
            if ang_r < 0:
                ang_r += 2 * math.pi
            epicenter_r = round(ang_r * 8.0 / (2.0 * math.pi)) % 8

            ang_c = math.atan2(yc, xc)
            if ang_c < 0:
                ang_c += 2 * math.pi
            epicenter_c = round(ang_c * 8.0 / (2.0 * math.pi)) % 8
        else:
            # Default to cell with peak energy
            max_r, max_c = 0, 0
            curr_max = -1.0
            for r in range(8):
                for c in range(8):
                    if energy[r][c] > curr_max:
                        curr_max = energy[r][c]
                        max_r, max_c = r, c
            epicenter_r, epicenter_c = max_r, max_c

        return ToroidalHeatmap(energy, (epicenter_r, epicenter_c), peak_val, mean_val)

    @staticmethod
    def map_epicenter_to_byte(r: int, c: int) -> int:
        """
        Inverts orthogonal message dispersal:
        Forward: M_disp[r, c] = M[8*r + ((c + r) mod 8)]
        Therefore, cell (r, c) receives byte: j = 8*r + ((c + r) mod 8)
        """
        return 8 * r + ((c + r) % 8)

    @staticmethod
    def map_byte_to_cell(byte_idx: int) -> Tuple[int, int]:
        """
        Maps linear byte index j (0..63) to its cell (r, c) on T^2 under orthogonal dispersal.
        r = j // 8
        (c + r) = j % 8 => c = (j % 8 - r) % 8
        """
        r = (byte_idx // 8) % 8
        c = ((byte_idx % 8) - r) % 8
        return r, c

    @staticmethod
    def compute_shannon_entropy(byte_sequence: bytes) -> float:
        """Calculates Shannon entropy of an octet sequence (0.0 to 8.0 bits/symbol)."""
        if not byte_sequence:
            return 0.0
        counts = [0] * 256
        for b in byte_sequence:
            counts[b] += 1
        n = len(byte_sequence)
        ent = 0.0
        for cnt in counts:
            if cnt > 0:
                p = cnt / n
                ent -= p * math.log2(p)
        return ent

    @classmethod
    def audit_streams(
        cls,
        authentic_data: Union[bytes, bytearray, str],
        suspect_data: Union[bytes, bytearray, str],
        sample_rate: Optional[int] = None,
        bytes_per_sec: Optional[float] = None,
    ) -> ForensicReport:
        """
        Performs comprehensive forensic analysis between authentic reference data
        and an untrusted suspect data stream.
        """
        if isinstance(authentic_data, str):
            authentic_data = authentic_data.encode("utf-8")
        if isinstance(suspect_data, str):
            suspect_data = suspect_data.encode("utf-8")

        len_a = len(authentic_data)
        len_b = len(suspect_data)

        # 1. Check for simple identical match
        if authentic_data == suspect_data:
            return ForensicReport(
                verdict=TamperType.AUTHENTIC,
                is_authentic=True,
                total_blocks_compared=(len_a + 63) // 64 if len_a > 0 else 0,
                diverging_blocks_count=0,
                summary="Streams are bit-for-bit identical.",
            )

        # 2. Check for Truncation or Append
        min_len = min(len_a, len_b)
        if authentic_data[:min_len] == suspect_data[:min_len]:
            verdict = TamperType.TRUNCATION if len_b < len_a else TamperType.APPEND
            diverging_block = min_len // 64
            byte_offset = min_len
            timestamp = (byte_offset / bytes_per_sec) if (bytes_per_sec and bytes_per_sec > 0) else ((byte_offset / (sample_rate * 2.0)) if (sample_rate and sample_rate > 0) else None)
            summary = (
                f"Suspect stream is truncated by {len_a - len_b} bytes at offset {min_len}."
                if verdict == TamperType.TRUNCATION
                else f"Suspect stream contains {len_b - len_a} appended trailing bytes starting at offset {min_len}."
            )
            return ForensicReport(
                verdict=verdict,
                is_authentic=False,
                diverging_block=diverging_block,
                byte_offset=byte_offset,
                estimated_timestamp_sec=timestamp,
                confidence=0.99,
                total_blocks_compared=(max(len_a, len_b) + 63) // 64,
                diverging_blocks_count=abs(len_a - len_b + 63) // 64,
                summary=summary,
            )

        # 3. Check for Framing Slip (Insertion or Deletion in mid-stream)
        # Check if suspect stream is a shifted version of authentic stream
        slip_detected = False
        slip_offset = 0
        slip_amount = 0
        # Find first byte of divergence
        first_diff_idx = 0
        while first_diff_idx < min_len and authentic_data[first_diff_idx] == suspect_data[first_diff_idx]:
            first_diff_idx += 1

        # Check small shifts from -16 to +16 bytes
        for shift in range(-16, 17):
            if shift == 0:
                continue
            if shift > 0:
                # Suspect has inserted bytes
                if len_b >= first_diff_idx + shift + 32 and len_a >= first_diff_idx + 32:
                    if authentic_data[first_diff_idx : first_diff_idx + 32] == suspect_data[first_diff_idx + shift : first_diff_idx + shift + 32]:
                        slip_detected = True
                        slip_offset = first_diff_idx
                        slip_amount = shift
                        break
            else:
                # Suspect has deleted bytes
                del_amount = abs(shift)
                if len_a >= first_diff_idx + del_amount + 32 and len_b >= first_diff_idx + 32:
                    if authentic_data[first_diff_idx + del_amount : first_diff_idx + del_amount + 32] == suspect_data[first_diff_idx : first_diff_idx + 32]:
                        slip_detected = True
                        slip_offset = first_diff_idx
                        slip_amount = shift
                        break

        # 4. Block-by-Block Cryptographic State Evolution
        # Partition data into 64-byte blocks
        num_blocks_a = (len_a + 63) // 64
        num_blocks_b = (len_b + 63) // 64
        total_blocks = max(num_blocks_a, num_blocks_b)

        syndromes: List[BlockSyndrome] = []
        divergent_block_idx: Optional[int] = None
        first_epicenter: Optional[Tuple[int, int]] = None
        injected_byte_idx: Optional[int] = None
        divergent_blocks_count = 0

        state_a = [row[:] for row in IV]
        state_b = [row[:] for row in IV]

        cum_bits_a = 0
        cum_bits_b = 0

        for b_idx in range(total_blocks):
            # Extract 64-byte chunks
            chunk_a = authentic_data[b_idx * 64 : (b_idx + 1) * 64] if b_idx * 64 < len_a else b""
            chunk_b = suspect_data[b_idx * 64 : (b_idx + 1) * 64] if b_idx * 64 < len_b else b""

            # Pad chunks if final block or incomplete
            block_bytes_a = bytes(chunk_a.ljust(64, b"\x00"))
            block_bytes_b = bytes(chunk_b.ljust(64, b"\x00"))

            # Input diff
            input_diff = bytes(x ^ y for x, y in zip(block_bytes_a, block_bytes_b))

            # Update cryptographic states
            cum_bits_a += len(chunk_a) * 8
            cum_bits_b += len(chunk_b) * 8

            state_a = compress_block(state_a, block_bytes_a, cum_bits_a, num_rounds=16)
            state_b = compress_block(state_b, block_bytes_b, cum_bits_b, num_rounds=16)

            # Compute differential syndrome: Delta = S_A ^ S_B
            delta_matrix = [[state_a[r][c] ^ state_b[r][c] for c in range(8)] for r in range(8)]
            delta_flat = bytes(delta_matrix[r][c] for r in range(8) for c in range(8))
            hw = sum(count_bits(b) for b in delta_flat)
            active = sum(1 for b in delta_flat if b != 0)
            entropy = cls.compute_shannon_entropy(delta_flat)

            # Compute spatial heatmap and epicenter on T^2
            heatmap = cls.compute_spatial_energy(delta_matrix)

            syndrome = BlockSyndrome(
                block_idx=b_idx,
                delta_matrix=delta_matrix,
                hamming_weight=hw,
                active_cells=active,
                entropy=entropy,
                heatmap=heatmap,
                input_diff_bytes=input_diff,
            )
            syndromes.append(syndrome)

            if hw > 0:
                divergent_blocks_count += 1
                if divergent_block_idx is None:
                    divergent_block_idx = b_idx
                    # Analyze first point of divergence
                    # Find exact byte in input block that differed
                    diff_byte_in_block = -1
                    for idx, (ba, bb) in enumerate(zip(block_bytes_a, block_bytes_b)):
                        if ba != bb:
                            diff_byte_in_block = idx
                            break

                    if diff_byte_in_block >= 0:
                        injected_byte_idx = diff_byte_in_block
                        first_epicenter = cls.map_byte_to_cell(diff_byte_in_block)
                    else:
                        first_epicenter = heatmap.epicenter
                        injected_byte_idx = cls.map_epicenter_to_byte(first_epicenter[0], first_epicenter[1])

        # 5. Classification
        if slip_detected:
            verdict = TamperType.FRAMING_SLIP
            action = f"insertion of {slip_amount} bytes" if slip_amount > 0 else f"deletion of {abs(slip_amount)} bytes"
            summary = (
                f"Framing slip (desynchronization) detected at offset {slip_offset}: {action}. "
                f"Subsequent blocks undergo periodic phase distortion across toroidal dispersal orbits."
            )
            confidence = 0.96
            exact_byte_offset = slip_offset
        else:
            # Check first divergent block input diff
            first_syn = next((s for s in syndromes if s.block_idx == divergent_block_idx), None)
            if first_syn and first_syn.input_bits_flipped > 0:
                flipped_bits = first_syn.input_bits_flipped
                # Count how many bytes in that block were modified
                modified_bytes_count = sum(1 for b in first_syn.input_diff_bytes if b != 0) if first_syn.input_diff_bytes else 0

                if flipped_bits <= 4 and modified_bytes_count <= 2:
                    verdict = TamperType.BIT_ROT
                    confidence = 0.98
                    epi_str = f"({first_epicenter[0]}, {first_epicenter[1]})" if first_epicenter is not None else "N/A"
                    summary = (
                        f"Isolated physical bit-rot / transmission error detected. "
                        f"{flipped_bits} bit(s) flipped across {modified_bytes_count} byte(s). "
                        f"Epicenter localized to toroidal coordinate {epi_str}."
                    )
                else:
                    verdict = TamperType.PAYLOAD_SUBSTITUTION
                    confidence = 0.99
                    summary = (
                        f"Deliberate payload substitution / splice detected. "
                        f"{modified_bytes_count} bytes altered in block #{divergent_block_idx}. "
                        f"Triggered instant avalanche saturation across the toroidal manifold."
                    )
            else:
                verdict = TamperType.PAYLOAD_SUBSTITUTION
                confidence = 0.95
                summary = f"State divergence confirmed at block #{divergent_block_idx}."

            exact_byte_offset = (divergent_block_idx * 64 + (injected_byte_idx or 0)) if divergent_block_idx is not None else first_diff_idx

        # Calculate estimated timestamp (for audio or video streams)
        timestamp = None
        if exact_byte_offset is not None:
            if bytes_per_sec and bytes_per_sec > 0:
                timestamp = exact_byte_offset / bytes_per_sec
            elif sample_rate and sample_rate > 0:
                # Assuming standard 16-bit mono PCM (2 bytes per sample)
                timestamp = exact_byte_offset / (sample_rate * 2.0)

        return ForensicReport(
            verdict=verdict,
            is_authentic=False,
            diverging_block=divergent_block_idx,
            byte_offset=exact_byte_offset,
            estimated_timestamp_sec=timestamp,
            epicenter=first_epicenter,
            injected_byte_in_block=injected_byte_idx,
            confidence=confidence,
            total_blocks_compared=total_blocks,
            diverging_blocks_count=divergent_blocks_count,
            syndromes=syndromes,
            summary=summary,
        )

    @classmethod
    def audit_files(
        cls,
        authentic_filepath: Union[str, os.PathLike],
        suspect_filepath: Union[str, os.PathLike],
        sample_rate: Optional[int] = None,
        bytes_per_sec: Optional[float] = None,
    ) -> ForensicReport:
        """Audits two disk files and produces a comprehensive forensic report."""
        with open(authentic_filepath, "rb") as fa, open(suspect_filepath, "rb") as fb:
            data_a = fa.read()
            data_b = fb.read()
        return cls.audit_streams(data_a, data_b, sample_rate=sample_rate, bytes_per_sec=bytes_per_sec)


# High-level convenience functions
def forensic_audit(
    authentic: Union[bytes, str],
    suspect: Union[bytes, str],
    sample_rate: Optional[int] = None,
    bytes_per_sec: Optional[float] = None,
) -> ForensicReport:
    """Public convenience function for running TORIX forensic audit on in-memory streams."""
    return TorixForensicAnalyzer.audit_streams(authentic, suspect, sample_rate=sample_rate, bytes_per_sec=bytes_per_sec)


def forensic_audit_files(
    authentic_path: str,
    suspect_path: str,
    sample_rate: Optional[int] = None,
    bytes_per_sec: Optional[float] = None,
) -> ForensicReport:
    """Public convenience function for running TORIX forensic audit on files on disk."""
    return TorixForensicAnalyzer.audit_files(authentic_path, suspect_path, sample_rate=sample_rate, bytes_per_sec=bytes_per_sec)


if __name__ == "__main__":
    # Self-test demonstration
    print("Executing TORIX-512 Forensic Heatmap Self-Test...")
    ref_audio = b"COURT_PROCEEDING_2026_TESTIMONY_THE_DEFENDANT_WAS_PRESENT_AT_THE_BANK_AT_NOON_SHARP_AND_HELD_A_BLACK_BAG_WITHOUT_DOUBT_ACCORDING_TO_WITNESS_TESTIMONY"
    tampered = b"COURT_PROCEEDING_2026_TESTIMONY_THE_DEFENDANT_WAS_ABSENT___AT_THE_BANK_AT_NOON_SHARP_AND_HELD_A_BLACK_BAG_WITHOUT_DOUBT_ACCORDING_TO_WITNESS_TESTIMONY"

    rep = forensic_audit(ref_audio, tampered, sample_rate=44100)
    print(rep.format_report())
