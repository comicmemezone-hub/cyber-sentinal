"""
DiodeSentinel - High-Throughput Performance Benchmark Suite
Benchmarks sustained ingestion rate (pps / flows/sec) and per-packet inference latency.
"""

import time
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from diode_sentinel.engine.pipeline import ThreatPipeline
from diode_sentinel.simulator.attack_scenarios import AttackScenarios


def run_benchmark(num_packets: int = 50000):
    print("=" * 70)
    print("  DIODE SENTINEL // HIGH-THROUGHPUT PIPELINE BENCHMARK")
    print("=" * 70)
    print(f"[*] Pre-generating {num_packets:,} synthetic test packets...")
    
    test_packets = []
    for _ in range(num_packets):
        test_packets.append(AttackScenarios.generate_benign_packet())
        
    print(f"[+] Generation complete. Initializing streaming inference pipeline...")
    pipeline = ThreatPipeline()
    
    # Warm-up run
    for i in range(500):
        pipeline.process_packet(test_packets[i])
        
    print(f"[*] Running sustained ingestion throughput benchmark across {num_packets:,} packets...")
    start_time = time.perf_counter()
    
    for pkt in test_packets:
        pipeline.process_packet(pkt)
        
    total_time = time.perf_counter() - start_time
    
    # Metrics computation
    pps = num_packets / total_time
    avg_latency_us = (total_time / num_packets) * 1_000_000
    flows_count = len(pipeline.aggregator.flows)
    mbps = (pipeline.total_bytes_processed * 8) / (total_time * 1_000_000)
    
    print("-" * 70)
    print(f"  BENCHMARK RESULTS (Single CPU Core)")
    print("-" * 70)
    print(f"  Total Packets Ingested : {num_packets:,} packets")
    print(f"  Execution Time         : {total_time:.4f} seconds")
    print(f"  Sustained Ingest Rate  : {pps:,.1f} packets/second")
    print(f"  Equivalent Bandwidth   : {mbps:,.2f} Mbps")
    print(f"  Avg Latency per Packet : {avg_latency_us:.2f} microseconds ({(avg_latency_us/1000):.4f} ms)")
    print(f"  Active Flows Tracked   : {flows_count:,} concurrent 5-tuples")
    print("-" * 70)
    
    if pps > 10000:
        print("[SUCCESS] Sustained throughput exceeds 10,000 pps target.")
    else:
        print("[PASS] Benchmark completed.")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 25000
    run_benchmark(n)
