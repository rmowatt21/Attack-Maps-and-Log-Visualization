# Attack-Maps-and-Log-Visualization

Entra ID (Azure) Authentication Success

In this scenario, we want to visually look for login attempts by users that are accessing the VM successfully. We set this up in Azure Sentinel and we’re going to use this query: 

SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)

This query analyzes sign-in logs to give you a clear picture of user activity. Here’s a simple breakdown:  

1. **SigninLogs** 📜: This is where Azure AD sign-in data is stored.  

2. **`where ResultType == 0`** ✅: Filters the data to only include successful sign-ins (ResultType 0 means success).  

3. **`summarize LoginCount = count()`** 🔢: Counts how many successful logins happened and groups them by specific details, such as:  
   - **Identity** 👤: The user who logged in.  
   - **Latitude** 🌍 & **Longitude** 📍: The geographic location of the user’s sign-in.  
   - **City** 🏙️: The city where the sign-in occurred.  
   - **Country** 🌎: The country where the sign-in occurred.  

4. **`project`** 🎯: This step selects and renames the final data you want to display:  
   - **Identity** 👥: The user’s name or ID.  
   - **Latitude & Longitude** 📍🌍: Their location.  
   - **City & Country** 🏙️🌍: Where they logged in from.  
   - **LoginCount** 🔢: The number of successful logins from that user.  
   - **`friendly_label`** 🏷️: A friendly label that combines the user's name with their city and country for easier reference.  

![image](https://github.com/user-attachments/assets/127d9cf8-5df7-4081-9f6d-242a153b0364)

Log into the Azure Portal
Go to Sentinel → Threat Management → Workbooks → Add a Workbook.
In advance we can go ahead and paste the Json code into the analytical log so we can use KQL to query the results. This will allow us to have a visual idea of what the json code and KQL results are giving us. 

Entra ID (Azure) Authentication Failures

We’re looking at the unsuccessful login attempts by users trying to access the system or the VM in this scenario. This will give a good indication of the bad actors that are trying to access the system. 

SigninLogs
| where ResultType != 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)

1. **SigninLogs** 📜: This is where Azure AD sign-in data is stored.

2. **`where ResultType != 0`** ❌: Filters the data to only include failed sign-ins (ResultType other than 0 means failure).

3. **`summarize LoginCount = count()`** 🔢: Counts the number of failed logins, grouped by specific details, such as:  
   - **Identity** 👤: The user who attempted to log in.
   - **Latitude** 🌍 & **Longitude** 📍: The geographic location of the failed sign-in.
   - **City** 🏙️: The city where the failed sign-in occurred.
   - **Country** 🌎: The country where the failed sign-in occurred.

4. **`project`** 🎯: This step selects and renames the final data you want to display:  
   - **Identity** 👥: The user’s name or ID.
   - **Latitude & Longitude** 📍🌍: Their location.
   - **City & Country** 🏙️🌍: Where the failed sign-in occurred.
   - **LoginCount** 🔢: The number of failed logins from that user.
   - **`friendly_label`** 🏷️: A friendly label that combines the user's name with their city and country for easier reference.

![image](https://github.com/user-attachments/assets/29334fab-224b-47f6-9657-f23d1e76a540)

Log into the Azure Portal
Go to Sentinel → Threat Management → Workbooks → Add a Workbook.
In advance we can go ahead and paste the Json code into the analytical log so we can use KQL to query the results. This will allow us to have visuals on the attempts in the login failures. 

VM Authentication Failures

In this scenario, we’re looking at the failed login attempts in the VM. 

let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;

GeoIP Watchlist 🌍:
let GeoIPDB_FULL = _GetWatchlist("geoip");
This loads a geolocation database to map IP addresses to location details like country, city, latitude, and longitude.

Filtering Failed Logins ❌:

DeviceLogonEvents: This table contains the logon data for devices.
where ActionType == "LogonFailed" 🛑: Filters the data to only include failed logon attempts.
Sorting Events ⏳:

order by TimeGenerated desc 🕒: Sorts the events by the most recent time of occurrence.
GeoIP Enrichment 🌍🔍:

evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network): This function enriches the failed logon events by looking up the geographic location of the RemoteIP (the IP from which the logon attempt originated).
Summarizing Data 🔢:

summarize LoginAttempts = count() 🔢: Counts the number of failed login attempts, grouped by the following fields:
RemoteIP 🌐: The source IP address of the failed login attempt.
City 🏙️: The city associated with the IP address.
Country 🌎: The country associated with the IP address.
friendly_location 🏷️: A combined label of city and country for easier readability (e.g., "London (UK)").
Latitude 📍 and Longitude 🌍: Geographical coordinates of the IP.

![image](https://github.com/user-attachments/assets/6ca9d629-eb1f-4bab-a927-0d8748a2fec2)








