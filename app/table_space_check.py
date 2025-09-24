import sys

def check_tablespace_free_space(file_path):
    """
    Reads a file with tablespace information, checks the 'PCT_FREE_OF_MAX' column,
    and flags tablespaces with less than 15% free space of max.

    Args:
        file_path (str): The path to the file containing the tablespace data.
    """
    low_space_tables = []  # list of (name, pct_free)
    header_found = False
    headers = []
    name_index = -1
    pct_free_of_max_index = -1

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # --- FIX: Pre-process lines to merge broken data rows ---
        processed_lines = []
        for line in lines:
            # If a line starts with whitespace, it's a continuation of the previous line.
            if line.strip() and (line.startswith(' ') or line.startswith('\t')):
                if processed_lines:
                    processed_lines[-1] = processed_lines[-1].strip() + " " + line.strip()
            else:
                processed_lines.append(line)
        # --- END FIX ---

        for line in processed_lines:
            # Find the header line that contains the column names
            if 'TABLESPACE_NAME' in line and 'PCT_FREE_OF_MAX' in line and not header_found:
                header_found = True
                headers = line.strip().split()
                try:
                    name_index = headers.index('TABLESPACE_NAME')
                    pct_free_of_max_index = headers.index('PCT_FREE_OF_MAX')
                except ValueError:
                    print("Error: Required columns 'TABLESPACE_NAME' or 'PCT_FREE_OF_MAX' not found in header.")
                    return
                continue # Skip to the next line

            if header_found and line.strip() and not line.startswith('-') and not line.startswith('db_name') and not line.startswith('SQL*Plus') and 'rows selected' not in line:
                parts = line.strip().split()

                if len(parts) > max(name_index, pct_free_of_max_index):
                    tablespace_name = parts[name_index]
                    try:
                        pct_free_str = parts[pct_free_of_max_index]
                        pct_free = float(pct_free_str)

                        if pct_free < 15.0:
                            low_space_tables.append((tablespace_name, pct_free))
                    except (ValueError, IndexError):
                        # Skip lines where the relevant data isn't a valid number
                        continue

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return

    # Print the result
    if low_space_tables:
        formatted = ",".join([f"{name}({pct:.2f}%)" for name, pct in low_space_tables])
        print(f"❌ {formatted} have less than 15% space left")
    else:
        print("✅ All tablespaces have more than 15% free space.")

# --- FIX: Read filename from command line ---
if __name__ == "__main__":
    # Check if a filename was provided as an argument
    if len(sys.argv) > 1:
        file_to_check = sys.argv[1]
        check_tablespace_free_space(file_to_check)
    else:
        print("Usage: python table_space_check.py <path_to_file>")
# --- END FIX ---