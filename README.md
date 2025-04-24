# Software-Testing-Project
Unified Fuzzing Framework for Django and BLE Applications

## Folder Structure

```plaintext
Software-Testing-Project/
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
```

## Setup Instructions

1. Install dependencies
```bash
pip install -r requirements.txt
```

2. Setup Django Application
```bash
cd django
```

3. Start the Django server
```bash
python manage.py runserver
```

4. Setup BLE Smart Lock
```bash
cd ble
```

5. For Windows:
```bash
.\install.bat
```

6. For macOS/Linux:
```bash
bash install.sh
```

## Running the Unified Fuzzer

1. Fuzz both Django and BLE targets
```bash
python unified_fuzzer.py --target both
```

2. Fuzz only Django
```bash
python unified_fuzzer.py --target django
```
3. Fuzz only BLE
```bash
python unified_fuzzer.py --target ble
```