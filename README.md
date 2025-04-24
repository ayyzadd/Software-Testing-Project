# Software-Testing-Project
Unified Fuzzing Framework for Django and BLE Applications

Directory Structure
fuzzing-project/
├── unified_fuzzer.py         # Main unified fuzzer
├── requirements.txt          # Combined requirements
├── ble/                      # BLE Smart Lock files
│   ├── BLEClient.py
│   ├── Smartlock.py
│   ├── UserInterface.py
│   ├── Input1.json           # BLE test seeds
│   └── ...                   # Other BLE files
├── django/                   # Django Web App files
│   ├── fuzzer2.py
│   ├── test_driver2.py
│   ├── input.json            # Django test seeds
│   └── ...                   # Other Django files
└── results/                  # Fuzzing results directory

Setup Instructions

1. Installation
# Install dependencies
pip install -r requirements.txt

2. Setup Django Application
# Navigate to the Django directory
cd django

# Start the Django server
python manage.py runserver

3. Setup BLE Smart Lock
# Navigate to the BLE directory
cd ble

# For Windows:
.\install.bat

# For macOS/Linux:
bash install.sh

Running the Unified Fuzzer

# Fuzz both Django and BLE targets
python unified_fuzzer.py --target both

# Fuzz only Django
python unified_fuzzer.py --target django

# Fuzz only BLE
python unified_fuzzer.py --target ble