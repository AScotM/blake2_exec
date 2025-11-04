#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import time

def main():
    parser = argparse.ArgumentParser(description='BLAKE2 file hasher')
    parser.add_argument('-a', '--algorithm', default='blake2b', 
                       choices=['blake2b', 'blake2s', 'blake2b-256', 'blake2b-384', 'blake2b-512'],
                       help='hash algorithm')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='process directories recursively')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                       help='number of parallel jobs')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='verbose output')
    parser.add_argument('--check', metavar='FILE',
                       help='read hashes from FILE and verify them')
    parser.add_argument('--min-size', type=int,
                       help='minimum file size in bytes')
    parser.add_argument('--max-size', type=int,
                       help='maximum file size in bytes')
    parser.add_argument('--exclude', action='append',
                       help='exclude patterns')
    parser.add_argument('-o', '--output', 
                       help='output file (default: stdout)')
    parser.add_argument('--format', default='bsd', choices=['bsd', 'gnu'],
                       help='output format')
    parser.add_argument('paths', nargs='*', default=['.'])
    args = parser.parse_args()

    if args.check:
        verify_hashes(args.check, args.algorithm, args.verbose)
        return

    files = collect_files(args.paths, args.recursive, args.min_size, args.max_size, args.exclude)
    
    output_file = open(args.output, 'w') if args.output else sys.stdout
    
    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = []
            for file_path in files:
                future = executor.submit(process_file, file_path, args.algorithm, args.verbose, args.format)
                futures.append(future)
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        output_file.write(result + '\n')
                except Exception as e:
                    if args.verbose:
                        print(f"# ERROR: {e}", file=sys.stderr)
    else:
        for file_path in files:
            result = process_file(file_path, args.algorithm, args.verbose, args.format)
            if result:
                output_file.write(result + '\n')
    
    if args.output:
        output_file.close()

def collect_files(paths, recursive, min_size, max_size, exclude_patterns):
    files = []
    for path_arg in paths:
        path = Path(path_arg)
        if path.is_file() and should_include_file(path, min_size, max_size, exclude_patterns):
            files.append(path)
        elif path.is_dir():
            pattern = path.rglob('*') if recursive else path.iterdir()
            for file_path in pattern:
                if file_path.is_file() and should_include_file(file_path, min_size, max_size, exclude_patterns):
                    files.append(file_path)
    return files

def should_include_file(file_path, min_size, max_size, exclude_patterns):
    try:
        stat = file_path.stat()
        if min_size and stat.st_size < min_size:
            return False
        if max_size and stat.st_size > max_size:
            return False
        if exclude_patterns and any(pattern in str(file_path) for pattern in exclude_patterns):
            return False
        return True
    except OSError:
        return False

def verify_hashes(check_file, algorithm, verbose):
    with open(check_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Support both BSD (hash  filename) and GNU (hash *filename) formats
            if '  ' in line:
                parts = line.split('  ', 1)
            elif ' *' in line:
                parts = line.split(' *', 1)
            else:
                if verbose:
                    print(f"Line {line_num}: invalid format", file=sys.stderr)
                continue
                
            if len(parts) == 2:
                expected_hash, file_path = parts
                try:
                    actual_hash = hash_file(Path(file_path), algorithm)
                    if actual_hash == expected_hash:
                        print(f"{file_path}: OK")
                    else:
                        print(f"{file_path}: FAILED")
                        if verbose:
                            print(f"  Expected: {expected_hash}")
                            print(f"  Got:      {actual_hash}")
                except Exception as e:
                    print(f"{file_path}: ERROR")
                    if verbose:
                        print(f"  {e}")

def process_file(file_path, algorithm, verbose, output_format):
    try:
        start_time = time.time()
        hash_val = hash_file(file_path, algorithm)
        elapsed = time.time() - start_time
        
        if output_format == 'bsd':
            result = f"{hash_val}  {file_path}"
        else:  # gnu
            result = f"{hash_val} *{file_path}"
            
        if verbose:
            size = file_path.stat().st_size
            print(f"# {file_path}: {size} bytes, {elapsed:.3f}s", file=sys.stderr)
            
        return result
    except Exception as e:
        if verbose:
            print(f"# ERROR {file_path}: {e}", file=sys.stderr)
        return None

def hash_file(file_path, algorithm):
    if algorithm == 'blake2b':
        h = hashlib.blake2b()
    elif algorithm == 'blake2s':
        h = hashlib.blake2s()
    elif algorithm == 'blake2b-256':
        h = hashlib.blake2b(digest_size=32)
    elif algorithm == 'blake2b-384':
        h = hashlib.blake2b(digest_size=48)
    elif algorithm == 'blake2b-512':
        h = hashlib.blake2b(digest_size=64)
    else:
        h = hashlib.blake2b()  # default
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

if __name__ == '__main__':
    main()
