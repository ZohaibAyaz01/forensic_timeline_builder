import os
import sys
import json
import csv
from datetime import datetime
from pathlib import Path
from collections import defaultdict, namedtuple
import argparse

# Import colorama for cross-platform colored output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    print("Warning: colorama not installed. Using plain text output.")
    COLORAMA_AVAILABLE = False
    # Create dummy color objects
    class DummyColor:
        RED = YELLOW = GREEN = BLUE = CYAN = MAGENTA = WHITE = ""
        RESET = ""
    Fore = Style = DummyColor()

# File event structure
FileEvent = namedtuple('FileEvent', ['timestamp', 'event_type', 'filepath', 'size'])

class Colors:
    """Color constants for better organization"""
    if COLORAMA_AVAILABLE:
        HEADER = Fore.CYAN + Style.BRIGHT
        SUCCESS = Fore.GREEN
        WARNING = Fore.YELLOW
        ERROR = Fore.RED
        INFO = Fore.BLUE
        ACCENT = Fore.MAGENTA
        RESET = Style.RESET_ALL
    else:
        HEADER = SUCCESS = WARNING = ERROR = INFO = ACCENT = RESET = ""

class FileAnalyzer:
    """Handles file system analysis and timestamp extraction"""
    
    def _init_(self):
        self.supported_extensions = {
            '.txt', '.doc', '.docx', '.pdf', '.jpg', '.jpeg', '.png', '.gif',
            '.mp4', '.avi', '.mov', '.exe', '.dll', '.sys', '.log', '.xml',
            '.html', '.css', '.js', '.py', '.cpp', '.java', '.zip', '.rar'
        }
        self.scan_stats = {
            'total_files': 0,
            'analyzed_files': 0,
            'errors': 0,
            'total_size': 0
        }
    
    def analyze_directory(self, directory_path, recursive=True):
        """
        Analyze directory and extract file timestamps
        Args:
            directory_path (str): Path to analyze
            recursive (bool): Whether to scan subdirectories
        Returns:
            list: List of FileEvent objects
        """
        events = []
        directory = Path(directory_path)
        
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        print(f"{Colors.INFO}Scanning directory: {directory_path}{Colors.RESET}")
        
        # Use different iteration based on recursive flag
        files_to_process = directory.rglob('*') if recursive else directory.iterdir()
        
        for file_path in files_to_process:
            if file_path.is_file():
                self.scan_stats['total_files'] += 1
                try:
                    # Extract file information
                    file_events = self._extract_file_events(file_path)
                    events.extend(file_events)
                    self.scan_stats['analyzed_files'] += 1
                    
                    # Update progress for large directories
                    if self.scan_stats['total_files'] % 50 == 0:
                        print(f"{Colors.INFO}Processed {self.scan_stats['total_files']} files...{Colors.RESET}")
                        
                except (OSError, PermissionError) as e:
                    self.scan_stats['errors'] += 1
                    print(f"{Colors.WARNING}Error accessing {file_path}: {e}{Colors.RESET}")
        
        # Sort events chronologically
        events.sort(key=lambda x: x.timestamp)
        return events
    
    def _extract_file_events(self, file_path):
        """Extract creation, modification, and access events from a file"""
        events = []
        stat = file_path.stat()
        
        # Get file size and update total
        file_size = stat.st_size
        self.scan_stats['total_size'] += file_size
        
        # Extract timestamps (handling different OS behaviors)
        creation_time = getattr(stat, 'st_birthtime', stat.st_ctime)
        modification_time = stat.st_mtime
        access_time = stat.st_atime
        
        # Create events for each timestamp type
        events.append(FileEvent(
            timestamp=datetime.fromtimestamp(creation_time),
            event_type='CREATE',
            filepath=str(file_path),
            size=file_size
        ))
        
        # Only add modification event if different from creation
        if abs(modification_time - creation_time) > 1:  # 1 second tolerance
            events.append(FileEvent(
                timestamp=datetime.fromtimestamp(modification_time),
                event_type='MODIFY',
                filepath=str(file_path),
                size=file_size
            ))
        
        # Only add access event if significantly different
        if abs(access_time - max(creation_time, modification_time)) > 60:  # 1 minute tolerance
            events.append(FileEvent(
                timestamp=datetime.fromtimestamp(access_time),
                event_type='ACCESS',
                filepath=str(file_path),
                size=file_size
            ))
        
        return events

class TimelineVisualizer:
    """Handles timeline visualization and display"""
    
    def _init_(self):
        self.event_colors = {
            'CREATE': Colors.SUCCESS,
            'MODIFY': Colors.WARNING,
            'ACCESS': Colors.INFO
        }
    
    def display_timeline(self, events, limit=50, filter_type=None, start_date=None, end_date=None):
        """
        Display formatted timeline of events
        Args:
            events (list): List of FileEvent objects
            limit (int): Maximum events to display
            filter_type (str): Filter by event type
            start_date (datetime): Filter start date
            end_date (datetime): Filter end date
        """
        # Apply filters
        filtered_events = self._apply_filters(events, filter_type, start_date, end_date)
        
        if not filtered_events:
            print(f"{Colors.WARNING}No events match the specified criteria.{Colors.RESET}")
            return
        
        # Display header
        print(f"\n{Colors.HEADER}{'='*80}")
        print(f"FORENSIC TIMELINE - {len(filtered_events)} Events Found")
        print(f"{'='*80}{Colors.RESET}\n")
        
        # Display events (limited)
        display_events = filtered_events[:limit]
        
        for event in display_events:
            color = self.event_colors.get(event.event_type, Colors.RESET)
            timestamp_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            size_str = self._format_file_size(event.size)
            filename = Path(event.filepath).name
            
            print(f"[{timestamp_str}] {color}{event.event_type:7}{Colors.RESET} "
                  f"{filename:30} ({size_str})")
        
        # Show summary if events were limited
        if len(filtered_events) > limit:
            remaining = len(filtered_events) - limit
            print(f"\n{Colors.INFO}... and {remaining} more events{Colors.RESET}")
        
        # Display statistics
        self._display_statistics(filtered_events)
    
    def _apply_filters(self, events, filter_type, start_date, end_date):
        """Apply filters to event list"""
        filtered = events
        
        if filter_type:
            filtered = [e for e in filtered if e.event_type == filter_type.upper()]
        
        if start_date:
            filtered = [e for e in filtered if e.timestamp >= start_date]
        
        if end_date:
            filtered = [e for e in filtered if e.timestamp <= end_date]
        
        return filtered
    
    def _display_statistics(self, events):
        """Display timeline statistics"""
        if not events:
            return
        
        # Group events by type
        event_counts = defaultdict(int)
        total_size = 0
        
        for event in events:
            event_counts[event.event_type] += 1
            total_size += event.size
        
        # Time range
        start_time = events[0].timestamp
        end_time = events[-1].timestamp
        time_span = end_time - start_time
        
        print(f"\n{Colors.HEADER}TIMELINE STATISTICS{Colors.RESET}")
        print(f"Time Range: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}")
        print(f"Duration: {time_span}")
        print(f"Total Data Size: {self._format_file_size(total_size)}")
        
        print(f"\nEvent Distribution:")
        for event_type, count in event_counts.items():
            color = self.event_colors.get(event_type, Colors.RESET)
            percentage = (count / len(events)) * 100
            print(f"  {color}{event_type:7}{Colors.RESET}: {count:4} events ({percentage:.1f}%)")
    
    def _format_file_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

class TimelineExporter:
    """Handles exporting timeline data to various formats"""
    
    def export_to_csv(self, events, filename):
        """Export timeline to CSV file"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Timestamp', 'Event Type', 'File Path', 'File Size'])
                
                for event in events:
                    writer.writerow([
                        event.timestamp.isoformat(),
                        event.event_type,
                        event.filepath,
                        event.size
                    ])
            
            print(f"{Colors.SUCCESS}Timeline exported to {filename}{Colors.RESET}")
            return True
        except Exception as e:
            print(f"{Colors.ERROR}Export failed: {e}{Colors.RESET}")
            return False
    
    def export_to_json(self, events, filename):
        """Export timeline to JSON file"""
        try:
            timeline_data = {
                'export_timestamp': datetime.now().isoformat(),
                'total_events': len(events),
                'events': [
                    {
                        'timestamp': event.timestamp.isoformat(),
                        'event_type': event.event_type,
                        'filepath': event.filepath,
                        'size': event.size
                    }
                    for event in events
                ]
            }
            
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(timeline_data, jsonfile, indent=2, ensure_ascii=False)
            
            print(f"{Colors.SUCCESS}Timeline exported to {filename}{Colors.RESET}")
            return True
        except Exception as e:
            print(f"{Colors.ERROR}Export failed: {e}{Colors.RESET}")
            return False

class ForensicTimelineCLI:
    """Main CLI application class"""
    
    def _init_(self):
        self.analyzer = FileAnalyzer()
        self.visualizer = TimelineVisualizer()
        self.exporter = TimelineExporter()
        self.current_timeline = []
    
    def display_banner(self):
        """Display application banner"""
        banner = f"""
{Colors.HEADER}
___________                                .__         __________._               .__  .__                __________      ..__       .___            
\_   ____/_________   ____   ____   ____|| ____   \_    __/|| _____   ____ |  | || ____   ____   \_____   \__ _||  |    __| _/__________ 
 |    _)/  _ \  __ \/ __ \ /    \ /  ___/  |/ ___\    |    |   |  |/     \/ __ \|  | |  |/    \/ __ \   |    |  _/  |  \  |  |   / __ |/ __ \  __ 
 |     \(  <> )  | \/\  ___/|   |  \\__ \|  \  \___    |    |   |  |  Y Y  \  __/|  ||  |   |  \  __/   |    |   \  |  /  |  |/ // \  ___/|  | \/
 \___  / \/||    \___  >|  /___  >|\___  >   ||   ||||  /\__  >/||  /\__  >  |______  //||/\____ |\___  >|   
     \/                    \/     \/     \/        \/                      \/     \/             \/     \/          \/                    \/    \/       
{Colors.RESET}
        """
        print(banner)
    
    def display_main_menu(self):
        """Display main menu options"""
        menu = f"""
{Colors.HEADER}MAIN MENU{Colors.RESET}
{Colors.INFO}1.{Colors.RESET} Analyze Directory
{Colors.INFO}2.{Colors.RESET} View Current Timeline
{Colors.INFO}3.{Colors.RESET} Filter Timeline
{Colors.INFO}4.{Colors.RESET} Export Timeline
{Colors.INFO}5.{Colors.RESET} Statistics
{Colors.INFO}6.{Colors.RESET} Help
{Colors.INFO}0.{Colors.RESET} Exit
        """
        print(menu)
    
    def get_user_choice(self, prompt, valid_choices):
        """Get validated user input"""
        while True:
            try:
                choice = input(f"{Colors.ACCENT}{prompt}{Colors.RESET}").strip()
                if choice in valid_choices:
                    return choice
                else:
                    print(f"{Colors.WARNING}Invalid choice. Please select from: {', '.join(valid_choices)}{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{Colors.INFO}Exiting...{Colors.RESET}")
                sys.exit(0)
    
    def analyze_directory_menu(self):
        """Handle directory analysis menu"""
        print(f"\n{Colors.HEADER}DIRECTORY ANALYSIS{Colors.RESET}")
        
        # Get directory path
        while True:
            directory = input(f"{Colors.ACCENT}Enter directory path to analyze: {Colors.RESET}").strip()
            if directory and Path(directory).exists():
                break
            print(f"{Colors.ERROR}Directory not found. Please enter a valid path.{Colors.RESET}")
        
        # Ask for recursive scan
        recursive_choice = self.get_user_choice(
            "Scan subdirectories recursively? (y/n): ", ['y', 'n', 'yes', 'no']
        )
        recursive = recursive_choice.lower() in ['y', 'yes']
        
        # Perform analysis
        try:
            print(f"\n{Colors.INFO}Starting analysis...{Colors.RESET}")
            self.current_timeline = self.analyzer.analyze_directory(directory, recursive)
            
            print(f"\n{Colors.SUCCESS}Analysis complete!{Colors.RESET}")
            print(f"Found {len(self.current_timeline)} events")
            print(f"Analyzed {self.analyzer.scan_stats['analyzed_files']} files")
            
            if self.analyzer.scan_stats['errors'] > 0:
                print(f"{Colors.WARNING}Encountered {self.analyzer.scan_stats['errors']} errors{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.ERROR}Analysis failed: {e}{Colors.RESET}")
    
    def view_timeline_menu(self):
        """Handle timeline viewing menu"""
        if not self.current_timeline:
            print(f"{Colors.WARNING}No timeline data available. Please analyze a directory first.{Colors.RESET}")
            return
        
        print(f"\n{Colors.HEADER}VIEW TIMELINE{Colors.RESET}")
        
        # Get display limit
        try:
            limit = int(input(f"{Colors.ACCENT}Number of events to display (default 50): {Colors.RESET}") or 50)
        except ValueError:
            limit = 50
        
        self.visualizer.display_timeline(self.current_timeline, limit=limit)
    
    def filter_timeline_menu(self):
        """Handle timeline filtering menu"""
        if not self.current_timeline:
            print(f"{Colors.WARNING}No timeline data available. Please analyze a directory first.{Colors.RESET}")
            return
        
        print(f"\n{Colors.HEADER}FILTER TIMELINE{Colors.RESET}")
        
        # Event type filter
        print("Filter by event type:")
        print("1. CREATE events only")
        print("2. MODIFY events only") 
        print("3. ACCESS events only")
        print("4. All events (no filter)")
        
        filter_choice = self.get_user_choice("Select filter option: ", ['1', '2', '3', '4'])
        
        filter_type = None
        if filter_choice == '1':
            filter_type = 'CREATE'
        elif filter_choice == '2':
            filter_type = 'MODIFY'
        elif filter_choice == '3':
            filter_type = 'ACCESS'
        
        # Display limit
        try:
            limit = int(input(f"{Colors.ACCENT}Number of events to display (default 50): {Colors.RESET}") or 50)
        except ValueError:
            limit = 50
        
        self.visualizer.display_timeline(self.current_timeline, limit=limit, filter_type=filter_type)
    
    def export_timeline_menu(self):
        """Handle timeline export menu"""
        if not self.current_timeline:
            print(f"{Colors.WARNING}No timeline data available. Please analyze a directory first.{Colors.RESET}")
            return
        
        print(f"\n{Colors.HEADER}EXPORT TIMELINE{Colors.RESET}")
        print("1. Export to CSV")
        print("2. Export to JSON")
        
        export_choice = self.get_user_choice("Select export format: ", ['1', '2'])
        
        # Get filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if export_choice == '1':
            default_filename = f"timeline_{timestamp}.csv"
            filename = input(f"{Colors.ACCENT}CSV filename (default: {default_filename}): {Colors.RESET}") or default_filename
            self.exporter.export_to_csv(self.current_timeline, filename)
        else:
            default_filename = f"timeline_{timestamp}.json"
            filename = input(f"{Colors.ACCENT}JSON filename (default: {default_filename}): {Colors.RESET}") or default_filename
            self.exporter.export_to_json(self.current_timeline, filename)
    
    def show_statistics(self):
        """Display current timeline statistics"""
        if not self.current_timeline:
            print(f"{Colors.WARNING}No timeline data available. Please analyze a directory first.{Colors.RESET}")
            return
        
        self.visualizer._display_statistics(self.current_timeline)
    
    def show_help(self):
        """Display help information"""
        help_text = f"""
{Colors.HEADER}FORENSIC TIMELINE BUILDER - HELP{Colors.RESET}

{Colors.INFO}Purpose:{Colors.RESET}
This tool analyzes digital evidence directories to extract file system
timestamps and create a chronological timeline of file activities.

{Colors.INFO}Features:{Colors.RESET}
• Recursive directory scanning
• File creation, modification, and access time extraction
• Color-coded timeline visualization
• Event filtering and statistics
• Export to CSV and JSON formats

{Colors.INFO}Event Types:{Colors.RESET}
• CREATE: File creation events (green)
• MODIFY: File modification events (yellow)
• ACCESS: File access events (blue)

{Colors.INFO}Usage Tips:{Colors.RESET}
1. Start by analyzing a directory (option 1)
2. View the timeline to see chronological events
3. Use filters to focus on specific event types
4. Export results for further analysis or reporting

{Colors.INFO}File Size Display:{Colors.RESET}
File sizes are displayed in human-readable format (B, KB, MB, GB).

{Colors.INFO}Supported Platforms:{Colors.RESET}
Windows, macOS, and Linux are all supported.
        """
        print(help_text)
    
    def run(self):
        """Main application loop"""
        self.display_banner()
        
        # Main menu loop
        while True:
            self.display_main_menu()
            choice = self.get_user_choice("Select option: ", ['0', '1', '2', '3', '4', '5', '6'])
            
            if choice == '0':
                print(f"{Colors.SUCCESS}Thank you for using Forensic Timeline Builder!{Colors.RESET}")
                break
            elif choice == '1':
                self.analyze_directory_menu()
            elif choice == '2':
                self.view_timeline_menu()
            elif choice == '3':
                self.filter_timeline_menu()
            elif choice == '4':
                self.export_timeline_menu()
            elif choice == '5':
                self.show_statistics()
            elif choice == '6':
                self.show_help()
            
            # Pause before returning to menu
            input(f"\n{Colors.ACCENT}Press Enter to continue...{Colors.RESET}")

def main():
    """Main entry point"""
    # Handle command line arguments
    parser = argparse.ArgumentParser(description='Forensic Timeline Builder')
    parser.add_argument('--directory', '-d', help='Directory to analyze')
    parser.add_argument('--recursive', '-r', action='store_true', help='Recursive scan')
    parser.add_argument('--export', '-e', choices=['csv', 'json'], help='Export format')
    parser.add_argument('--output', '-o', help='Output filename')
    
    args = parser.parse_args()
    
    # Create CLI application
    app = ForensicTimelineCLI()
    
    # Handle command line mode
    if args.directory:
        print("Running in command-line mode...")
        try:
            events = app.analyzer.analyze_directory(args.directory, args.recursive)
            app.visualizer.display_timeline(events)
            
            if args.export:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = args.output or f"timeline_{timestamp}.{args.export}"
                
                if args.export == 'csv':
                    app.exporter.export_to_csv(events, filename)
                else:
                    app.exporter.export_to_json(events, filename)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        # Run interactive mode
        app.run()

if __name__ == "_main_":
    main()