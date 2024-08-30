from pathlib import Path
import os
import shutil
import csv
from datetime import datetime, timedelta


# Defining global variables
USERNAME = os.getenv("USER")
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Directories (.log and .csv)
ARCHIVE_DIR = Path(__file__).resolve().parent.parent.parent / 'phishing_catcher_archives'
FINAL_REPO_PATH = Path(__file__).resolve().parent.parent.parent / 'phishing_catcher_final_files'
FINAL_DIRECTORIES = [ARCHIVE_DIR, FINAL_REPO_PATH]
ROOT_PATH = f'/home/{USERNAME}'

LOG_FILES = {
    'potential': Path(__file__).resolve().parent.parent / f'potential_domains.log',
    'suspicious': Path(__file__).resolve().parent.parent / f'suspicious_domains.log',
    'problematic': Path(__file__).resolve().parent.parent / f'problematic_domains.log',
}

FINAL_FILE_PATHS = {
    'potential': FINAL_REPO_PATH/'phishing_catcher_potential_domains.csv',
    'suspicious': FINAL_REPO_PATH/'phishing_catcher_suspicious_domains.csv',
    'problematic': FINAL_REPO_PATH/'phishing_catcher_problematic_domains.csv',
}


class LogManager:
    def __init__(self, log_files, final_repo_path, final_file_paths, archive_dir, max_file_size):
        self.log_files = log_files
        self.final_repo_path = final_repo_path
        self.final_file_paths = final_file_paths
        self.archive_dir = archive_dir
        self.max_file_size = max_file_size


    def delete_expired_certificates(self):
        """Deletes lines in the CSV files whose certificates have expired for more than 3 months and 12 hours."""
        max_cert_duration = timedelta(days=90, hours=12)
        now = datetime.now()

        for file_path in self.final_file_paths.values():
            try:
                lines_to_keep = []
                with open(file_path, mode='r', newline='') as csv_file:
                    reader = csv.reader(csv_file)
                    for row in reader:
                        try:
                            # Certificate creation date (index 1)
                            date_creation_str = row[1].strip() if row[1] else None
                            if date_creation_str:
                                date_creation = datetime.strptime(date_creation_str, '%Y-%m-%d %H:%M:%S')
                                if now - date_creation <= max_cert_duration:
                                    lines_to_keep.append(row)
                        except ValueError:
                            print(f"Invalid date in row: {row}")

                # Write a new file
                with open(file_path, mode='w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerows(lines_to_keep)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")


    def log_rotate(self):
        """
        Rotates the logs if they exceed the max size or at midnight.
        Archives the old logs and updates the final csv file with the new data.
        """
        file_sizes = {key: os.path.getsize(path) for key, path in self.log_files.items()}
        current_time = datetime.now()
        current_date = current_time.strftime("%Y-%m-%d %H:%M:%S")  # Get the current date
        today = datetime.today()
        midnight = datetime(today.year, today.month, today.day, 0, 0, 0)

        # Rotation condition: if it is midnight or if a file exceeds the maximum size.
        if any(size >= self.max_file_size for size in file_sizes.values()) or str(midnight) == current_date: 
            self._append_logs_to_final_files()
            self._archive_logs(current_time)
            # print("\n[DEBUG] Rotation ok\n")
            self._clear_logs()
            self.delete_expired_certificates()        
        # print(f"\n[DEBUG] {str(midnight)}, {current_date}\n")


    def _append_logs_to_final_files(self):
        """Appends the content of the log files to the respective FINAL CSV files."""
        # Make sure the directory exists before writing to the files.
        for directory in FINAL_DIRECTORIES:
            if not os.path.exists(directory):
                os.makedirs(directory)
            
        for key, log_file_path in self.log_files.items():
            try:
                if not os.path.exists(self.final_file_paths[key]):
                    # Create the file if it doesn't exist
                    open(self.final_file_paths[key], 'w').close()

                with open(log_file_path, 'r') as log_file:
                    log_content = log_file.read()

                # Adding new domains to the csv file 
                with open(self.final_file_paths[key], 'a') as final_file:
                    final_file.write(log_content)

            except Exception as e:
                print(f"Error appending logs to final file for {key}: {e}")

        # Uncomment these lines to enable Git commands (untested)
        # subprocess.run(['git', 'pull'], cwd=self.final_repo_path)
        # subprocess.run(['git', 'add', *self.final_file_paths.values()], cwd=self.final_repo_path)
        # subprocess.run(['git', 'commit', '-m', f'Log rotation at {datetime.now()}'], cwd=self.final_repo_path)
        # subprocess.run(['git', 'push'], cwd=self.final_repo_path)


    def _archive_logs(self, current_time):
        """Archives the log files and stores them in the archive directory."""
        for key, log_file_path in self.log_files.items():
            archive_name = f"{key}_domains_{current_time.strftime('%Y%m%d_%H%M%S')}"
            archive_path = os.path.join(self.archive_dir, archive_name)

            try:
                # Create an archive (.tar.gz)
                shutil.make_archive(archive_path, 'gztar', root_dir='.', base_dir=log_file_path)
            except Exception as e:
                print(f"Error archiving {key} log file: {e}")


    def _clear_logs(self):
        """Clears the log files by truncating them."""
        for log_file_path in self.log_files.values():
            try:
                # Empty the work file (.log)
                open(log_file_path, 'w').close()
            except Exception as e:
                print(f"Error clearing log file {log_file_path}: {e}")