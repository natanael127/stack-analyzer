import os
import re
import json
import argparse
from dataclasses import dataclass, replace
from typing import List, Dict, Optional, Set

@dataclass
class Function:
    name: str
    file: str
    def serialize(self):
        return {
            "file": self.file,
            "function": self.name,
        }

@dataclass
class StackStats:
    usage: int = 0
    static: bool = True
    bounded: bool = True
    def serialize(self):
        return {
            "usage": self.usage,
            "static": self.static,
            "bounded": self.bounded,
        }

@dataclass
class StackData:
    stats: Optional[StackStats] = None
    untracked: Optional[Set[str]] = None

    def serialize(self):
        output = {}
        if self.stats:
            output = self.stats.serialize()
        if self.untracked and len(self.untracked) > 0:
            output["untracked"] = list(self.untracked)
        return output

@dataclass
class CallGraph:
    function: Function
    calls: list[Function]

@dataclass
class CflowLine:
    function: Function
    level: int

@dataclass
class StackUsage:
    function: Function
    self_stack: Optional[StackData] = None
    total_stack: Optional[StackData] = None

    def serialize(self):
        output = self.function.serialize()
        if self.self_stack:
            output["self"] = self.self_stack.serialize()
        if self.total_stack:
            output["total"] = self.total_stack.serialize()
        return output

@dataclass
class FunctionReport:
    result: StackUsage
    called: List[StackUsage]

    def serialize(self):
        output = self.result.serialize()
        output["calls"] = []
        if self.called:
            for called in sorted(self.called, key=lambda x: (x.function.file, x.function.name)):
                output["calls"].append(called.serialize())
        return output

def parse_su_file(file_path: str) -> List[StackUsage]:
    """
    Analyzes a .su file to obtain stack usage information.
    
    Args:
        file_path: Path to the .su file to be analyzed
        
    Returns:
        List of StackUsage objects containing stack usage information
    """
    stack_usages = []

    with open(file_path, 'r') as file:
        for line in file:
            # Expected format: file:line:col:function_name bytes type
            match = re.match(r'([^:]+):(\d+):(\d+):(\S+)\s+(\d+)\s+(\S+)', line.strip())
            if match:
                source_file, _, _, function_name, usage, usage_type = match.groups()
                function = Function(file=source_file, name=function_name)
                is_static = False
                explicitly_bounded = False
                if "static" in usage_type:
                    is_static = True
                if "bounded" in usage_type:
                    explicitly_bounded = True
                stack_stats = StackStats(
                    usage=int(usage),
                    static=is_static,
                    bounded=explicitly_bounded or is_static
                )
                stack_data = StackData(stats=stack_stats)
                stack_usage = StackUsage(
                    function=function,
                    self_stack=stack_data,
                )
                stack_usages.append(stack_usage)

    return stack_usages

def find_su_files(directory: str) -> List[StackUsage]:
    """
    Recursively navigates through a directory looking for .su files and extracts stack usage information.
    
    Args:
        directory: Root directory to start the search
        
    Returns:
        List of StackUsage objects containing stack usage information from all files found
    """
    all_stack_usages = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.su'):
                file_path = os.path.join(root, file)
                try:
                    stack_usages = parse_su_file(file_path)
                    all_stack_usages.extend(stack_usages)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
    
    return all_stack_usages

def parse_cflow_line(line: str) -> Optional[CflowLine]:
    """
    Analyzes a line from the cflow file to extract function call information.
    
    Args:
        line: Line from the cflow file
        
    Returns:
        CflowLine object containing line information, or None if the line doesn't contain valid information
    """
    output = None

    # Complete match {indent_level} function_name() at source_file:line_number
    match = re.match(r'{\s*(\d+)\}\s+(\S+)\(\).*at\s+([^:]+):(\d+)', line)
    if match:
        indent_level = int(match.group(1))
        function_name = match.group(2)
        source_file = match.group(3)
        output = CflowLine(
            level=indent_level,
            function=Function(name=function_name, file=source_file)
        )
    # Incomplete match {indent_level} function_name()
    else:
        match = re.match(r'{\s*(\d+)\}\s+(\S+)\(\)', line)
        if match:
            indent_level = int(match.group(1))
            function_name = match.group(2)
            output = CflowLine(
                level=indent_level,
                function=Function(name=function_name, file="")
            )

    return output

def parse_cflow_file(file_path: str) -> List[CallGraph]:
    """
    Analyzes a file generated by the cflow tool to extract the function call graph.
    
    Args:
        file_path: Path to the cflow file to be analyzed
        
    Returns:
        List of CallGraph objects representing the call graph
    """
    call_graphs = []
    call_stack = []

    with open(file_path, 'r') as file:
        for line in file:
            parsed = parse_cflow_line(line)
            if not parsed:
                continue

            current_function = parsed.function

            # Adjust call stack based on indentation level
            while len(call_stack) > parsed.level:
                call_stack.pop()

            # Create CallGraph entry for the parent function if it exists
            if call_stack and parsed.level > 0:
                parent = call_stack[-1]
                # Find if we already have a CallGraph for this parent
                parent_graph = next((cg for cg in call_graphs if cg.function == parent), None)

                if parent_graph:
                    # Check if this function call is already in the parent's calls
                    if not any(f == current_function for f in parent_graph.calls):
                        parent_graph.calls.append(current_function)
                else:
                    # Create new CallGraph for this parent
                    call_graphs.append(CallGraph(function=parent, calls=[current_function]))

            # Add current function to call stack
            call_stack.append(current_function)

            # If this is a new root function, create a CallGraph for it
            if parsed.level == 0 and not any(cg.function == current_function for cg in call_graphs):
                call_graphs.append(CallGraph(function=current_function, calls=[]))

    return call_graphs

def get_total_stack(function: Function, call_graph_map: Dict[str, CallGraph], 
    stack_usage_map: Dict[str, StackData], visited: Set[str] = None) -> StackData:
    """
    Calculates the total stack usage for a function, considering recursive calls.
    
    Args:
        function: Function to calculate stack usage for
        call_graph_map: Mapping of functions to their call graphs
        stack_usage_map: Mapping of functions to their stack usage data
        visited: Set of already visited functions to avoid infinite loops
        
    Returns:
        Total stack usage in bytes
    """
    if visited is None:
        visited = set()

    # Create a unique key for the function
    function_key = get_function_key(function)

    # If we've already visited this function, return neutral stack data
    if function_key in visited:
        return StackData(stats=StackStats())

    # Mark this function as visited
    visited.add(function_key)

    # Get the stack stats for this function
    accumulated = None
    stack_data = stack_usage_map.get(function_key)
    if stack_data is not None:
        accumulated = replace(stack_data.stats)

    # Get the call graph for this function
    call_graph = call_graph_map.get(function_key)
    max_call_path_usage = 0
    untracked = set()
    if call_graph and accumulated:
        for called_function in call_graph.calls:
            called_key = get_function_key(called_function)
            # Skip self-recursive calls as they're already accounted for in the base usage
            if called_key != function_key:
                call_data = get_total_stack(
                    called_function,
                    call_graph_map,
                    stack_usage_map,
                    visited.copy()
                )
                if call_data.stats:
                    max_call_path_usage = max(
                        max_call_path_usage, call_data.stats.usage
                    )
                    accumulated.static = accumulated.static and call_data.stats.static
                    accumulated.bounded = accumulated.bounded and call_data.stats.bounded
                else:
                    untracked.add(called_function.name)
                if call_data.untracked:
                    untracked.update(call_data.untracked)
        accumulated.usage += max_call_path_usage

    return StackData(
        stats=accumulated,
        untracked=untracked,
    )

def get_function_key(function: Function) -> str:
    """
    Generates a unique key for a function based on its name and file.
    
    Args:
        function: Function object to generate the key for
        
    Returns:
        Unique string key for the function
    """
    return f"{function.name}:{function.file}"

def generate_report_data(stack_usages: List[StackUsage], call_graphs: List[CallGraph]) -> List[FunctionReport]:
    """
    Generates a JSON report with stack analysis data.
    
    Args:
        stack_usages: List of stack usage information
        call_graphs: List of call graph information
        
    Returns:
        List of FunctionReport objects with stack usage information for each function
    """
    # Create mapping for easier lookup
    stack_usage_map = {get_function_key(su.function): su.self_stack for su in stack_usages}
    call_graph_map = {get_function_key(cg.function): cg for cg in call_graphs}

    # Create the report data
    report_data = []

    for su in stack_usages:
        # Calculate total stack usage for this function
        total_stack = get_total_stack(su.function, call_graph_map, stack_usage_map)

        # Get the list of called functions
        call_graph = call_graph_map.get(get_function_key(su.function))
        called_functions = []

        if call_graph:
            for called_func in call_graph.calls:
                called_functions.append(StackUsage(
                    function=called_func,
                    total_stack=get_total_stack(
                        called_func, call_graph_map, stack_usage_map
                    )
                ))
        # Create the entry for this function
        entry = FunctionReport(
            StackUsage(
                function=su.function,
                self_stack=su.self_stack,
                total_stack=total_stack
            ),
            called=called_functions
        )

        report_data.append(entry)

    return report_data

def save_json_report(report_data: List[FunctionReport], output_path: str):
    """
    Saves the JSON report to a file.

    Args:
        report_data: List of FunctionReport objects
        output_path: Path where the file will be saved
    """
    report_data.sort(key=lambda x: (x.result.function.file, x.result.function.name))
    json_data = [report.serialize() for report in report_data]
    with open(output_path, 'w') as file:
        json.dump(json_data, file, indent=2)

def main():
    """
    Main function that processes command-line arguments and executes stack usage analysis.
    """
    parser = argparse.ArgumentParser(description='Analyze stack usage from compiler output and cflow files')
    parser.add_argument('--su-dir', required=True, help='Directory to recursively search for .su files')
    parser.add_argument('--cflow-file', required=True,
        help='Path to the cflow output file (options --print-level and --format=gnu are required for good parsing)'
    )
    parser.add_argument('--output', default='stack_analysis.json', help='Path to output JSON report file (default: %(default)s)')

    args = parser.parse_args()

    stack_usages = find_su_files(args.su_dir)
    print(f"Found {len(stack_usages)} stack usage records")

    call_graphs = parse_cflow_file(args.cflow_file)
    print(f"Found {len(call_graphs)} call graph entries")

    save_json_report(generate_report_data(stack_usages, call_graphs), args.output)
    print(f"JSON report saved to {args.output}")

if __name__ == "__main__":
    main()
