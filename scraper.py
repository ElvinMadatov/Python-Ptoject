from docx import Document
from bs4 import BeautifulSoup
import requests
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By















current_date = datetime.datetime.now()
current_year = current_date.year

def validate_cve_format(cve_input):
    numbers = []
    numbers_str = []
    numbers_str.clear()
    numbers.clear()

    if "-" not in cve_input or cve_input.count("-") != 2:
        return "CVE format should be like CVE-YYYY-NNNN1\nTry a new one"

    parts = cve_input.split("-")
    if len(parts) != 3:
        return "CVE format should be like CVE-YYYY-NNNN2\nTry a new one"
    
    year_str = parts[1]
    id_str = parts[2]

    if not year_str.isdigit() or not id_str.isdigit():
        return "ID should contain just numbers"

    year = int(year_str)
    if year >= current_year:
        return "Year is far from us\nEnter id again"
    elif year <= 1999:
        return "There is no CVEs before 1999 ;)\nTry a new one"
    if len(id_str) < 4:
        return "ID must be 4 or more digits!"
    if int(id_str) == 0:
        return "ID cannot contain all zeros"

    return None


















def req_mitre_org(cve_input):
    validation_error = validate_cve_format(cve_input)
    if validation_error:
        return validation_error

    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_input}"
    mitre_response = requests.get(mitre_url).text
    mitre_soup = BeautifulSoup(mitre_response, 'html.parser')

    description_tag = mitre_soup.find(string="Description")
    description = description_tag.find_next('td').get_text(strip=True) if description_tag else "No description found"

    references = set()
    for ref in mitre_soup.find_all('li'):
        for url in ref.find_all('a', href=True):
            references.add(f'<a href="{url["href"]}" target="_blank">{url["href"]}</a>')

    result = f"<b>Description:</b><br>{description}<br><br><b>References:</b><br>"
    if references:
        result += "<br>".join(sorted(references))
    else:
        result += f"There is no referred link for {cve_input}"
    
    return result















def req_vulmon(cve_input):
    url = f'https://vulmon.com/vulnerabilitydetails?qid={cve_input}'
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        content = ""

        body_tag = soup.find('body', class_='Cust-Site')
        if body_tag:
            content_div = body_tag.find('div', class_='ui main container Cust-Site-content')
            if content_div:
                content_div1 = content_div.find('div', class_='ui stackable grid')
                if content_div1:
                    content_div2 = content_div1.find('div', class_='thirteen wide column')
                    if content_div2:
                        ui_segments = content_div2.find_all('div', class_='ui segment')

                        if ui_segments:
                            last_segment = ui_segments[-1]
                            # content += "<b>Last Segment Content:</b><br>"
                            # content += last_segment.get_text(strip=True) + "<br><br>"

                            if len(ui_segments) > 1:
                                second_segment = ui_segments[1]
                                # content += "<b>Second Segment Content:</b><br>"
                                # content += second_segment.get_text(strip=True) + "<br><br>"

                        p_tag = content_div2.find('p', string=lambda x: x and "The SMBv1 server in Microsoft Windows Vista SP2" in x)
                        if p_tag:
                            # content += "<b>Specific Description:</b><br>"
                            # content += p_tag.get_text(strip=True) + "<br><br>"

                            # Include clickable links for URLs
                            for link in content_div2.find_all('a', href=True):
                                content += f'<a href="{link["href"]}" target="_blank">{link["href"]}</a><br>'
        
        return content
    else:
        return f'Failed to retrieve the webpage. Status code: {response.status_code}'

    
    
    
    
    
    
    
    
    
    
def req_nist(cve_number):
    # Define the base URL for NIST CVE detail page
    detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_number}"

    try:
        # Send a GET request to the CVE detail page
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36'
        }
        response = requests.get(detail_url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        return {'error': f"Failed to retrieve data for {cve_number}: {e}"}

    # Parse the response HTML
    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract CVSS score
    cvss_score_element = soup.find('a', class_='label label-danger')
    cvss_score = cvss_score_element.string.strip() if cvss_score_element else "N/A"

    # Extract severity
    severity_element = soup.find('span', {'data-testid': 'vuln-cvssv3-base-score-severity'})
    severity = severity_element.text.strip() if severity_element else "N/A"

    # Extract published date
    published_date_element = soup.find('span', {'data-testid': 'vuln-published-on'})
    published_date = published_date_element.text.strip() if published_date_element else "N/A"

    # Extract last modified date
    last_modified_date_element = soup.find('span', {'data-testid': 'vuln-last-modified-on'})
    last_modified_date = last_modified_date_element.text.strip() if last_modified_date_element else "N/A"

    # Extract description
    description_element = soup.find('p', {'data-testid': 'vuln-description'})
    description = description_element.text.strip() if description_element else "N/A"

    # Extract affected assets
    affected_assets = []
    table = soup.find('table', {'data-testid': 'vuln-software-list-table'})
    if table:
        for row in table.find_all('tr')[1:]:  # Skip header row
            cols = row.find_all('td')
            if len(cols) > 1:
                vendor = cols[0].text.strip()
                product = cols[1].text.strip()
                affected_assets.append({'vendor': vendor, 'product': product})

    # Extract references
    references = []
    reference_list = soup.find('ul', {'data-testid': 'vuln-hyperlinks-list'})
    if not reference_list:
        reference_list = soup.find('div', {'class': 'vuln-hyperlinks'})

    if reference_list:
        for ref in reference_list.find_all('li'):
            link = ref.find('a')
            if link:
                references.append({
                    'title': link.text.strip(),
                    'url': link['href'].strip()
                })

    # Structure the output data in the required format
    cve_data = {
        'cve_number': cve_number,
        'cvss_score': f"{cvss_score}",
        'published_date': published_date,
        'last_modified_date': last_modified_date,
        'description': description,
        'affected_assets': affected_assets,
        'references': references,
    }

    return cve_data

def nist_format_output(cve_number):
    cve_data = req_nist(cve_number)
    # Formatting output to return as a string for display in the Flask app
    output = f"<b>{cve_data['cve_number']}</b><br>"
    output += f"<b>CVSS Score:</b> {cve_data['cvss_score']}<br>"
    output += f"<b>Published Date:</b> {cve_data['published_date']}<br>"
    output += f"<b>Last Modified Date:</b> {cve_data['last_modified_date']}<br><br>"
    
    output += "<b>DESCRIPTION</b><br>"
    output += f"{cve_data['description']}<br><br>"

    output += "<b>AFFECTED ASSETS</b><br>"
    for asset in cve_data['affected_assets']:
        output += f"Vendor: {asset['vendor']}, Product: {asset['product']}<br>"

    output += "<br><b>REFERENCES</b><br>"
    for ref in cve_data['references']:
        output += f'<a href="{ref["url"]}" target="_blank">{ref["title"]}</a><br>'

    return output














def req_vulner(cve_id):
    # Set up Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run without GUI
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    # Set up WebDriver
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

    try:
        # Go to the CVE page
        url = f'https://vulners.com/cve/{cve_id}'
        driver.get(url)
        
        # Wait for the page to load
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        # Get the HTML content of the page
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')

        # Extract details like title, description, and scores
        title_element = soup.find('h1', class_='css-csuvea-header-Content-title')
        title = title_element.get_text(strip=True) if title_element else 'No title'

        paragraphs = soup.find_all('p')
        specific_description = 'No specific description found'
        for paragraph in paragraphs:
            text = paragraph.get_text(strip=True)
            if "SMBv1 server" in text or "Internet Explorer" in text:
                specific_description = text
                break

        # Extract scores
        def find_score(label):
            label_element = soup.find('p', class_='MuiTypography-root MuiTypography-body2 css-4mixid', string=label)
            if label_element:
                score_pane = label_element.find_parent('div', class_='css-1an2tjf-ScorePane-container')
                if score_pane:
                    score_element = score_pane.find('span', class_='css-aa1gsu-ScoreIndicator-score')
                    return score_element.get_text(strip=True) if score_element else f'No {label} score'
            return f'No {label} label found'

        cvss2_score = find_score('CVSS2')
        cvss3_score = find_score('CVSS3')
        ai_score = find_score('AI Score')
        epss_score = find_score('EPSS')

        # Extract references and make them clickable
        references_section = soup.find('h2', class_='MuiTypography-root MuiTypography-h2 css-1gayvte-References-head')
        if references_section:
            references_list = references_section.find_next_sibling('div', class_='MuiPaper-root MuiPaper-elevation MuiPaper-rounded MuiPaper-elevation0 css-8tgesj-References-paper')
            references = [f'<a href="{a["href"]}" target="_blank">{a.get_text(strip=True)}</a>' for a in references_list.find_all('a')] if references_list else []
        else:
            references = []

        # Format the output for display
        result = f"<b>{title}</b><br>"
        result += f"<b>Specific Description:</b><br>{specific_description}<br><br>"
        result += f"<b>CVSS2 Score:</b> {cvss2_score}<br>"
        result += f"<b>CVSS3 Score:</b> {cvss3_score}<br>"
        result += f"<b>AI Score:</b> {ai_score}<br>"
        result += f"<b>EPSS Score:</b> {epss_score}<br><br>"

        result += "<b>References:</b><br>"
        result += "<br>".join(references)
        
        return result
    finally:
        driver.quit()

        















def check_exploit_db(cve_id):
    url = f"https://www.exploit-db.com/search?cve={cve_id}&draw=1&columns%5B0%5D%5Bdata%5D=date_published"
    
    headers = {
        "authority": "www.exploit-db.com",
        "accept": "application/json, text/javascript, */*; q=0.01",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check if the request was successful
    except requests.RequestException as e:
        return {'error': f"Error fetching data: {e}"}

    data = response.json()
    records_total = data.get("recordsTotal", 0)

    if records_total != 0:
        exploits = data.get("data", [])
        return {'records_total': records_total, 'exploits': exploits}
    else:
        return {'records_total': 0, 'exploits': []}
    



