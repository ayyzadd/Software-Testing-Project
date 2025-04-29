# Software-Testing-Project
Unified Fuzzing Framework for Django and BLE Applications

## Folder Structure

```plaintext
Software-Testing-Project/
├── unified_fuzzer.py         # Main unified fuzzer
├── unified_test_driver.py    # Main unified test driver
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

## Tech Stack
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.1.12-092E20?logo=django&logoColor=white)
![Bluetooth LE](https://img.shields.io/badge/Bluetooth%20LE-5.0-0082FC?logo=bluetooth&logoColor=white)
![Asyncio](https://img.shields.io/badge/Asyncio-3.4.3+-0082FC?logo=python&logoColor=white)
![Bleak](https://img.shields.io/badge/Bleak-0.14.0-303030?logo=bluetooth&logoColor=white)
![NiceGUI](https://img.shields.io/badge/NiceGUI-1.0.0+-00BFFF?logo=python&logoColor=white)
![Requests](https://img.shields.io/badge/Requests-2.26.0-009688?logo=python&logoColor=white)
![Coverage](https://img.shields.io/badge/Coverage-6.0.0-83B81A?logo=python&logoColor=white)

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
python test_driver_unified.py
```

2. Fuzz only Django
```bash
python unified_test_driver.py --target django
```

3. Run Django-only with a specific mutation type
```bash
python unified_fuzzer.py --target django --forced-mutation class_object_injection
```

4. Fuzz only BLE
```bash
python unified_test_driver.py --target ble 
```