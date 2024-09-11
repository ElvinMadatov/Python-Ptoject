from flask import Flask, request, jsonify, send_file, make_response, render_template
import io
import docx
from scraper import req_mitre_org, req_vulmon, req_nist, req_vulner, check_exploit_db
import openai
import webbrowser
import threading

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scrape', methods=['POST'])
def scrape():
    query = request.form.get('query', '')
    file_format = request.form.get('format', 'txt')
    file_name = request.form.get('filename', 'output')

    if not query or not file_format or not file_name:
        return make_response("Missing parameters", 400)

    try:
        # Scrape data from all sources
        mitre_data = req_mitre_org(query)
        vulmon_data = req_vulmon(query)
        nist_data = req_nist(query)
        vulner_data = req_vulner(query)
        exploit_db_data = check_exploit_db(query)

        # Aggregate results
        combined_results = f"Mitre Data:\n{mitre_data}\n\nVulmon Data:\n{vulmon_data}\n\nNIST Data:\n{nist_data}\n\nVulners Data:\n{vulner_data}\n\nExploit DB Data:\n{exploit_db_data}"

        if file_format == 'txt':
            output = io.BytesIO()
            output.write(summary.encode('utf-8'))
            output.seek(0)
            return send_file(output, as_attachment=True, download_name=f"{file_name}.txt", mimetype='text/plain')

        elif file_format == 'docx':
            doc = docx.Document()
            doc.add_paragraph(summary)
            doc_stream = io.BytesIO()
            doc.save(doc_stream)
            doc_stream.seek(0)
            return send_file(doc_stream, as_attachment=True, download_name=f"{file_name}.docx", mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

        else:
            return make_response("Unsupported file format", 400)

    except Exception as e:
        return make_response(f"An error occurred: {str(e)}", 500)

@app.route('/summary', methods=['POST'])
def summary():
    query = request.form.get('query', '')

    if not query:
        return make_response("Missing query parameter", 400)

    try:
        # Scrape data from all sources
        mitre_data = req_mitre_org(query)
        vulmon_data = req_vulmon(query)
        # nist_data = req_nist(query)
        vulner_data = req_vulner(query)
        exploit_db_data = check_exploit_db(query)

        # Aggregate results
        combined_results = f"Vulners Data:\n{vulner_data}\n\nExploit DB Data:\n{exploit_db_data}"

        return jsonify({
                        'combined data': combined_results
                        })

    except Exception as e:
        return make_response(f"An error occurred: {str(e)}", 500)

def open_browser():
    url = 'http://127.0.0.1:5000/'
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"Failed to open browser: {e}")

if __name__ == '__main__':
    # Start the Flask app in a separate thread
    threading.Thread(target=open_browser).start()
    app.run(debug=True, host='0.0.0.0')
