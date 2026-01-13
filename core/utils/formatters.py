"""
Formatting Utilities

Provides functions for formatting various data types for display
and reporting purposes.
"""

import math
from typing import Union


def format_bytes(bytes_value: Union[int, float]) -> str:
    """
    Format bytes into human-readable string.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if bytes_value == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    unit_index = int(math.floor(math.log(bytes_value, 1024)))
    
    if unit_index >= len(units):
        unit_index = len(units) - 1
    
    size = bytes_value / (1024 ** unit_index)
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"


def format_time(seconds: Union[int, float]) -> str:
    """
    Format seconds into human-readable time string.
    
    Args:
        seconds: Number of seconds
        
    Returns:
        Formatted time string (e.g., "2h 30m 15s")
    """
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.0f}s"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days}d {hours}h"


def format_number(number: Union[int, float]) -> str:
    """
    Format number with thousands separators.
    
    Args:
        number: Number to format
        
    Returns:
        Formatted number string
    """
    if isinstance(number, float):
        return f"{number:,.2f}"
    else:
        return f"{number:,}"


def format_rate(rate: Union[int, float]) -> str:
    """
    Format rate with appropriate units.
    
    Args:
        rate: Rate value (per second)
        
    Returns:
        Formatted rate string (e.g., "1.5M H/s")
    """
    if rate < 1000:
        return f"{rate:.0f} H/s"
    elif rate < 1000000:
        return f"{rate/1000:.1f} K H/s"
    elif rate < 1000000000:
        return f"{rate/1000000:.1f} M H/s"
    else:
        return f"{rate/1000000000:.1f} G H/s"


def format_percentage(value: Union[int, float], total: Union[int, float]) -> str:
    """
    Format as percentage.
    
    Args:
        value: Value
        total: Total
        
    Returns:
        Percentage string
    """
    if total == 0:
        return "0.0%"
    
    percentage = (value / total) * 100
    return f"{percentage:.1f}%"


def format_table(data: list, headers: list, max_width: int = 80) -> str:
    """
    Format data as a table.
    
    Args:
        data: List of rows (each row is a list of values)
        headers: List of column headers
        max_width: Maximum table width
        
    Returns:
        Formatted table string
    """
    if not data:
        return "No data to display"
    
    # Calculate column widths
    col_count = len(headers)
    col_widths = [len(header) for header in headers]
    
    for row in data:
        for i, cell in enumerate(row):
            if i < col_count:
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Adjust for max width
    total_width = sum(col_widths) + (col_count - 1) * 3  # 3 spaces between columns
    if total_width > max_width:
        # Proportionally reduce column widths
        scale_factor = (max_width - (col_count - 1) * 3) / total_width
        col_widths = [max(5, int(w * scale_factor)) for w in col_widths]
    
    # Build table
    lines = []
    
    # Header
    header_line = " | ".join(headers[i].ljust(col_widths[i]) for i in range(col_count))
    lines.append(header_line)
    lines.append("-" * len(header_line))
    
    # Data rows
    for row in data:
        row_cells = []
        for i in range(min(col_count, len(row))):
            cell = str(row[i])
            if len(cell) > col_widths[i]:
                cell = cell[:col_widths[i]-3] + "..."
            row_cells.append(cell.ljust(col_widths[i]))
        
        lines.append(" | ".join(row_cells))
    
    return "\n".join(lines)
