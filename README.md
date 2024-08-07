
# VulnPulse - Vulnerability Rating App

## Overview

VulnPulse is a ReactJS application designed to help users search for vulnerabilities and view detailed information including the base score, base severity, and vector string. The app retrieves data from the [CVSS v3 JSON file](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cvss_v3/cvss_v3.json) maintained by Bugcrowd, providing up-to-date and comprehensive vulnerability ratings.

## Features

- **Search Vulnerabilities:** Input the name of a vulnerability to search for.
- **Fetch and Display Data:** Retrieve and display base score, base severity, and vector string.
- **Real-Time Data:** Ensure accurate and up-to-date vulnerability information from the CVSS v3 data source.

## Installation

To get started with VulnPulse locally, follow these steps:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/VulnPulse.git
   cd VulnPulse
   ```

2. **Install Dependencies:**

   Make sure you have [Node.js](https://nodejs.org/) installed, then run:

   ```bash
   npm install
   ```

3. **Run the Application:**

   Start the development server:

   ```bash
   npm start
   ```

   Open your browser and go to `http://localhost:3000` to see the application in action.

## Usage

1. **Access the App:**

   Navigate to the application in your web browser.

2. **Search for Vulnerabilities:**

   Enter the name of the vulnerability you want to search for in the input field and hit "Search."

3. **View Results:**

   If the vulnerability is found, the app will display the base score, base severity, and vector string.

## Data Source

The application fetches data from the CVSS v3 JSON file available [here](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cvss_v3/cvss_v3.json). This data includes detailed information about various vulnerabilities, including their ratings and metrics.

