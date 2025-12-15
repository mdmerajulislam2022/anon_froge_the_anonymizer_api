#Anonymizer API with Runtime Memory

This API has been updated to use runtime memory instead of PostgreSQL database for employee data storage.

## Changes Made

1. **Removed PostgreSQL dependency** - No longer connects to PostgreSQL database
2. **Added runtime memory storage** - Employee data is loaded into memory on startup
3. **Integrated AD data extraction** - Uses functions from `ad_db_extract_cronjob.py` to fetch employee data
4. **Employee data structure**:
   - `user_id`
   - `user_name` 
   - `user_firstname`
   - `user_lastname`
   - `user_jobtitle`
   - `user_city`
   - `user_primarysmtpaddress`
   - `user_businesstelephonenumber`
   - `user_displayname`

## Configuration

The application uses HashiCorp Vault for AD credentials:
- **Vault Path**: `home/ad_db`
- **Required Secrets**: `BASE_DN`, `DOMAIN`, `LDAP_SERVER`, `SUPPER_USER_PASSWD`, `SUPPER_user_id`

## Installation

```bash
pip install -r requirements.txt
```

## Running the API

```bash
python main.py
```

The API will be available at `http://localhost:8001`

## Data Loading

Employee data is loaded from Active Directory on application startup:
- Data is fetched using LDAP connection
- Filtered for valid records (non-empty firstname and displayname)
- Stored in runtime memory for fast access
- No database connection required during operation

## API Endpoints

- `GET /` - API information
- `GET /health` - Health check
- `POST /anonymize` - Anonymize text strings# anon_froge_the_anonymizer_api
