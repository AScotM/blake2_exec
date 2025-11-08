#!/usr/bin/env python3

import argparse
import hashlib
import os
import sys
import time
import fnmatch
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple, Optional, Dict, Any
import signal
import stat

class HashVerificationResult:
    OK = 0
    FAILED = 1
    ERROR = 2
    SKIPPED = 3

class FileHasher:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.processed_files = 0
        self.total_size = 0
        self.start_time = time.time()
        self._interrupted = False
        
        # Set up signal handling for graceful interruption
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        self._interrupted = True
        print("\nReceived interrupt signal, finishing current files...", file=sys.stderr)
    
    def should_continue(self) -> bool:
        return not self._interrupted

    def collect_files(self, paths: List[str], recursive: bool = False, 
                     min_size: Optional[int] = None, max_size: Optional[int] = None,
                     exclude_patterns: Optional[List[str]] = None) -> List[Path]:
        """Collect files to process with safety checks."""
        files: List[Path] = []
        seen_files: Set[Path] = set()
        exclude_patterns = exclude_patterns or []
        
        for path_arg in paths:
            if not self.should_continue():
                break
                
            try:
                path = Path(path_arg)
                
                if self.verbose:
                    print(f"# Processing path: {path} (exists: {path.exists()})", file=sys.stderr)
                
                if not path.exists():
                    if self.verbose:
                        print(f"# WARNING: Path does not exist: {path}", file=sys.stderr)
                    continue
                
                if path.is_file():
                    if self._should_include_file(path, min_size, max_size, exclude_patterns):
                        real_path = path.resolve()
                        if real_path not in seen_files:
                            files.append(path)
                            seen_files.add(real_path)
                            if self.verbose:
                                print(f"# Added file: {path}", file=sys.stderr)
                elif path.is_dir():
                    if self.verbose:
                        print(f"# Scanning directory: {path}", file=sys.stderr)
                    
                    if recursive:
                        pattern = path.rglob('*')
                    else:
                        pattern = path.iterdir()
                    
                    for file_path in pattern:
                        if not self.should_continue():
                            break
                            
                        try:
                            if (file_path.is_file() and 
                                self._should_include_file(file_path, min_size, max_size, exclude_patterns)):
                                
                                real_path = file_path.resolve()
                                if real_path not in seen_files:
                                    files.append(file_path)
                                    seen_files.add(real_path)
                                    if self.verbose and len(files) % 100 == 0:
                                        print(f"# Collected {len(files)} files so far...", file=sys.stderr)
                        except (OSError, PermissionError) as e:
                            if self.verbose:
                                print(f"# WARNING: Cannot access {file_path}: {e}", file=sys.stderr)
                else:
                    if self.verbose:
                        print(f"# WARNING: Not a file or directory: {path}", file=sys.stderr)
                        
            except (OSError, PermissionError, ValueError) as e:
                if self.verbose:
                    print(f"# ERROR: Cannot process path {path_arg}: {e}", file=sys.stderr)
        
        if self.verbose:
            print(f"# Total files collected: {len(files)}", file=sys.stderr)
        
        return files

    def _should_include_file(self, file_path: Path, min_size: Optional[int], 
                           max_size: Optional[int], exclude_patterns: List[str]) -> bool:
        """Determine if a file should be included based on filters."""
        try:
            file_stat = file_path.stat()
            
            # Check file size filters
            if min_size is not None and file_stat.st_size < min_size:
                if self.verbose:
                    print(f"# Skipping {file_path}: size {file_stat.st_size} < {min_size}", file=sys.stderr)
                return False
            if max_size is not None and file_stat.st_size > max_size:
                if self.verbose:
                    print(f"# Skipping {file_path}: size {file_stat.st_size} > {max_size}", file=sys.stderr)
                return False
            
            # Check exclusion patterns
            file_path_str = str(file_path)
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(file_path_str, pattern):
                    if self.verbose:
                        print(f"# Skipping {file_path}: matches exclude pattern '{pattern}'", file=sys.stderr)
                    return False
            
            return True
            
        except (OSError, PermissionError) as e:
            if self.verbose:
                print(f"# Cannot stat {file_path}: {e}", file=sys.stderr)
            return False

    def hash_file(self, file_path: Path, algorithm: str, max_file_size: int = 10 * 1024 * 1024 * 1024) -> str:
        """Calculate file hash with safety limits."""
        try:
            file_stat = file_path.stat()
            
            # Check file size limit (10GB default)
            if file_stat.st_size > max_file_size:
                raise ValueError(f"File too large: {file_stat.st_size} bytes (max: {max_file_size})")
            
            # Initialize hash algorithm
            hash_params = self._get_hash_parameters(algorithm)
            if algorithm.startswith('blake2b'):
                h = hashlib.blake2b(**hash_params)
            else:
                h = hashlib.blake2s(**hash_params)
            
            # Read file in chunks
            chunk_size = 64 * 1024  # 64KB chunks
            bytes_read = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    if not self.should_continue():
                        raise InterruptedError("Operation interrupted")
                    
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    h.update(chunk)
                    bytes_read += len(chunk)
                    
                    # Progress feedback for very large files
                    if self.verbose and file_stat.st_size > 100 * 1024 * 1024:  # >100MB
                        progress = (bytes_read / file_stat.st_size) * 100
                        print(f"# Progress: {file_path.name} - {progress:.1f}%", end='\r', file=sys.stderr)
            
            if self.verbose and file_stat.st_size > 100 * 1024 * 1024:
                print(file=sys.stderr)  # New line after progress
            
            return h.hexdigest()
            
        except (OSError, PermissionError, MemoryError, ValueError) as e:
            if self.verbose:
                print(f"# ERROR hashing {file_path}: {e}", file=sys.stderr)
            raise

    def _get_hash_parameters(self, algorithm: str) -> Dict[str, Any]:
        """Get parameters for hash algorithm."""
        if algorithm == 'blake2b':
            return {'digest_size': 64}
        elif algorithm == 'blake2s':
            return {'digest_size': 32}
        elif algorithm == 'blake2b-256':
            return {'digest_size': 32}
        elif algorithm == 'blake2b-384':
            return {'digest_size': 48}
        elif algorithm == 'blake2b-512':
            return {'digest_size': 64}
        else:
            return {'digest_size': 64}  # Default to blake2b-512

    def process_file(self, file_path: Path, algorithm: str, output_format: str) -> Optional[str]:
        """Process a single file and return hash string."""
        try:
            if self.verbose:
                print(f"# Processing: {file_path}", file=sys.stderr)
            
            start_time = time.time()
            hash_val = self.hash_file(file_path, algorithm)
            elapsed = time.time() - start_time
            
            if output_format == 'bsd':
                result = f"{hash_val}  {file_path}"
            else:  # gnu
                result = f"{hash_val} *{file_path}"
            
            # Update statistics
            self.processed_files += 1
            file_size = file_path.stat().st_size
            self.total_size += file_size
            
            if self.verbose:
                speed = file_size / elapsed if elapsed > 0 else 0
                print(f"# Completed: {file_path} - {file_size} bytes, {elapsed:.3f}s, {speed/1024/1024:.1f} MB/s", 
                      file=sys.stderr)
            
            return result
            
        except Exception as e:
            if self.verbose:
                print(f"# ERROR processing {file_path}: {e}", file=sys.stderr)
            return None

    def verify_hashes(self, check_file: Path, algorithm: str) -> Tuple[int, int, int, int]:
        """Verify hashes from a checksum file."""
        ok_count = failed_count = error_count = skipped_count = 0
        
        try:
            with open(check_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if not self.should_continue():
                        break
                        
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse hash line
                    file_path, expected_hash = self._parse_hash_line(line, line_num)
                    if not file_path:
                        skipped_count += 1
                        continue
                    
                    # Verify hash
                    result = self._verify_single_hash(Path(file_path), expected_hash, algorithm, line_num)
                    
                    if result == HashVerificationResult.OK:
                        ok_count += 1
                        print(f"{file_path}: OK")
                    elif result == HashVerificationResult.FAILED:
                        failed_count += 1
                        print(f"{file_path}: FAILED")
                    elif result == HashVerificationResult.ERROR:
                        error_count += 1
                        print(f"{file_path}: ERROR")
                    else:
                        skipped_count += 1
                        
        except FileNotFoundError:
            print(f"ERROR: Checksum file not found: {check_file}", file=sys.stderr)
            return 0, 0, 0, 0
        except OSError as e:
            print(f"ERROR: Cannot read checksum file: {e}", file=sys.stderr)
            return 0, 0, 0, 0
        
        return ok_count, failed_count, error_count, skipped_count

    def _parse_hash_line(self, line: str, line_num: int) -> Tuple[Optional[str], Optional[str]]:
        """Parse a hash line and return (file_path, expected_hash)."""
        # Support both BSD (hash  filename) and GNU (hash *filename) formats
        if '  ' in line:
            parts = line.split('  ', 1)
        elif ' *' in line:
            parts = line.split(' *', 1)
        elif ' ' in line:
            # Try single space as separator (fallback)
            parts = line.split(' ', 1)
        else:
            if self.verbose:
                print(f"# Line {line_num}: invalid format - '{line}'", file=sys.stderr)
            return None, None
        
        if len(parts) == 2:
            expected_hash, file_path = parts
            expected_hash = expected_hash.strip()
            file_path = file_path.strip()
            
            # Validate hash format (hexadecimal)
            if not all(c in '0123456789abcdefABCDEF' for c in expected_hash):
                if self.verbose:
                    print(f"# Line {line_num}: invalid hash format", file=sys.stderr)
                return None, None
                
            return file_path, expected_hash
        
        if self.verbose:
            print(f"# Line {line_num}: invalid format - '{line}'", file=sys.stderr)
        return None, None

    def _verify_single_hash(self, file_path: Path, expected_hash: str, 
                          algorithm: str, line_num: int) -> int:
        """Verify a single file's hash."""
        try:
            if not file_path.exists():
                if self.verbose:
                    print(f"# Line {line_num}: file not found - {file_path}", file=sys.stderr)
                return HashVerificationResult.ERROR
            
            actual_hash = self.hash_file(file_path, algorithm)
            
            if actual_hash == expected_hash:
                return HashVerificationResult.OK
            else:
                if self.verbose:
                    print(f"# Line {line_num}: hash mismatch for {file_path}", file=sys.stderr)
                    print(f"#   Expected: {expected_hash}", file=sys.stderr)
                    print(f"#   Got:      {actual_hash}", file=sys.stderr)
                return HashVerificationResult.FAILED
                
        except Exception as e:
            if self.verbose:
                print(f"# Line {line_num}: error verifying {file_path}: {e}", file=sys.stderr)
            return HashVerificationResult.ERROR

    def print_statistics(self):
        """Print processing statistics."""
        total_time = time.time() - self.start_time
        avg_speed = self.total_size / total_time if total_time > 0 else 0
        
        print(f"# Processed {self.processed_files} files", file=sys.stderr)
        print(f"# Total size: {self.total_size / 1024 / 1024:.2f} MB", file=sys.stderr)
        print(f"# Time elapsed: {total_time:.2f} seconds", file=sys.stderr)
        print(f"# Average speed: {avg_speed / 1024 / 1024:.2f} MB/s", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description='BLAKE2 file hasher - Secure and efficient file hashing utility',
        epilog='''
Examples:
  %(prog)s file.txt                    # Hash single file
  %(prog)s -r -j4 .                    # Hash all files recursively with 4 threads
  %(prog)s --check checksums.txt       # Verify hashes from file
  %(prog)s --min-size 1024 --exclude "*.tmp"  # Hash files >1KB, exclude .tmp files
        '''
    )
    parser.add_argument('-a', '--algorithm', default='blake2b', 
                       choices=['blake2b', 'blake2s', 'blake2b-256', 'blake2b-384', 'blake2b-512'],
                       help='hash algorithm (default: blake2b)')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='process directories recursively')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                       help='number of parallel jobs (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='verbose output')
    parser.add_argument('--check', metavar='FILE',
                       help='read hashes from FILE and verify them')
    parser.add_argument('--min-size', type=int,
                       help='minimum file size in bytes')
    parser.add_argument('--max-size', type=int,
                       help='maximum file size in bytes')
    parser.add_argument('--exclude', action='append',
                       help='exclude patterns (supports wildcards)')
    parser.add_argument('--max-file-size', type=int, default=10*1024*1024*1024,
                       help='maximum file size to process in bytes (default: 10GB)')
    parser.add_argument('-o', '--output', 
                       help='output file (default: stdout)')
    parser.add_argument('--format', default='bsd', choices=['bsd', 'gnu'],
                       help='output format (default: bsd)')
    parser.add_argument('paths', nargs='*', default=['.'],
                       help='files or directories to process (default: current directory)')
    
    args = parser.parse_args()

    # Validate arguments
    if args.jobs < 1:
        print("ERROR: Number of jobs must be at least 1", file=sys.stderr)
        sys.exit(1)
    
    if args.min_size and args.max_size and args.min_size > args.max_size:
        print("ERROR: Minimum size cannot be greater than maximum size", file=sys.stderr)
        sys.exit(1)
    
    if args.max_file_size <= 0:
        print("ERROR: Maximum file size must be positive", file=sys.stderr)
        sys.exit(1)

    hasher = FileHasher(verbose=args.verbose)
    exit_code = 0

    try:
        if args.check:
            if args.verbose:
                print(f"# Verifying hashes from: {args.check}", file=sys.stderr)
                print(f"# Algorithm: {args.algorithm}", file=sys.stderr)
            
            ok, failed, error, skipped = hasher.verify_hashes(Path(args.check), args.algorithm)
            
            if args.verbose:
                print(f"# Verification complete: {ok} OK, {failed} FAILED, {error} ERROR, {skipped} SKIPPED", 
                      file=sys.stderr)
            
            # Set exit code based on results
            if failed > 0 or error > 0:
                exit_code = 1
            elif ok == 0 and skipped > 0:
                exit_code = 2
                
        else:
            # Hash files
            if args.verbose:
                print(f"# Collecting files from: {args.paths}", file=sys.stderr)
                print(f"# Recursive: {args.recursive}", file=sys.stderr)
                print(f"# Min size: {args.min_size}", file=sys.stderr)
                print(f"# Max size: {args.max_size}", file=sys.stderr)
                print(f"# Exclude patterns: {args.exclude}", file=sys.stderr)
            
            files = hasher.collect_files(
                args.paths, args.recursive, args.min_size, args.max_size, args.exclude
            )
            
            if not files:
                print("No files found to process", file=sys.stderr)
                if args.verbose:
                    print("# Check that:")
                    print("# - The paths exist and are accessible")
                    print("# - Files match your size filters")
                    print("# - Files are not excluded by your patterns")
                sys.exit(1)
            
            if args.verbose:
                print(f"# Found {len(files)} files to process", file=sys.stderr)
                print(f"# Algorithm: {args.algorithm}", file=sys.stderr)
                print(f"# Parallel jobs: {args.jobs}", file=sys.stderr)
            
            # Setup output
            if args.output:
                output_file = open(args.output, 'w')
                if args.verbose:
                    print(f"# Writing output to: {args.output}", file=sys.stderr)
            else:
                output_file = sys.stdout
            
            try:
                if args.jobs > 1 and len(files) > 1:
                    # Parallel processing
                    if args.verbose:
                        print(f"# Starting parallel processing with {args.jobs} workers", file=sys.stderr)
                    
                    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
                        futures = {
                            executor.submit(hasher.process_file, file_path, args.algorithm, args.format): file_path 
                            for file_path in files if hasher.should_continue()
                        }
                        
                        for future in as_completed(futures):
                            if not hasher.should_continue():
                                break
                                
                            try:
                                result = future.result()
                                if result:
                                    print(result, file=output_file)
                                    output_file.flush()
                            except Exception as e:
                                if args.verbose:
                                    print(f"# ERROR: {e}", file=sys.stderr)
                else:
                    # Sequential processing
                    if args.verbose:
                        print("# Starting sequential processing", file=sys.stderr)
                    
                    for file_path in files:
                        if not hasher.should_continue():
                            break
                            
                        result = hasher.process_file(file_path, args.algorithm, args.format)
                        if result:
                            print(result, file=output_file)
                            output_file.flush()
                
                if args.verbose:
                    hasher.print_statistics()
                    
            finally:
                if args.output:
                    output_file.close()
    
    except KeyboardInterrupt:
        print("\nOperation interrupted by user", file=sys.stderr)
        exit_code = 130
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        exit_code = 1
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
