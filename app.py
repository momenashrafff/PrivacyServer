from flask_swagger_ui import get_swaggerui_blueprint
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import pytesseract
import spacy
import re
import shutil
import os
from spacy.matcher import Matcher
import random

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Regex patterns for additional PII
email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
phone_regex = r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"  # Matches phone numbers like (123) 456-7890 or 123-456-7890
ssn_regex = r"\d{3}-\d{2}-\d{4}"  # Matches Social Security Numbers (SSNs)

# Synonyms or placeholders for sensitive entities
location_synonyms = ["a popular city", "a well-known destination", "a major metropolitan area"]
date_synonyms = ["a specific date", "a special day", "a particular time"]
name_synonyms = ["a person", "someone", "an individual"]

# Load spaCy's pre-trained NER model for personal information detection
nlp = spacy.load("en_core_web_sm")

sensitive_patterns = [
    [{"ENT_TYPE": "PERSON"}],  # Match person names
    [{"ENT_TYPE": "GPE"}],     # Match locations
    [{"SHAPE": "ddd-ddd-dddd"}],  # Match phone numbers (e.g., 123-456-7890)
    [{"LIKE_EMAIL": True}],    # Match email addresses
    [{"LIKE_NUM": True, "LENGTH": 10}]  # Match 10-digit numbers (e.g., phone numbers without hyphens)
]

# Initialize the Matcher
matcher = Matcher(nlp.vocab)
for pattern in sensitive_patterns:
    matcher.add("SENSITIVE_INFO", [pattern])

# Set the path to the Tesseract executable (required for Windows)
tesseract_cmd = shutil.which("tesseract")
if tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
else:
    raise EnvironmentError("Tesseract is not installed or not found in PATH. Please install it and try again.")


# Regex patterns for detecting sensitive information
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
PHONE_PATTERN = r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b'
CREDIT_CARD_PATTERN = r'\b(?:\d{4}[- ]?){3}\d{4}\b'
SSN_PATTERN = r'\b\d{3}-\d{2}-\d{4}\b'
DOB_PATTERN = r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b'
PASSPORT_PATTERN = r'\b[A-Z]{1,2}\d{6,9}\b'
DRIVERS_LICENSE_PATTERN = r'\b[A-Z]{1,2}\d{6,8}\b'
BANK_ACCOUNT_PATTERN = r'\b\d{8,12}\b'
HEALTH_PATTERN = r'\b(?:patient|medical|diagnosis|prescription)\b'
INSURANCE_PATTERN = r'\bINS\d{6,9}\b'
BIOMETRIC_PATTERN = r'\b(?:fingerprint|retina scan|facial recognition)\b'
GENETIC_PATTERN = r'\b(?:DNA|genome|genetic)\b'
GPS_PATTERN = r'\b\d{1,3}\.\d{1,6}[° ]?[NS]?,?\s*\d{1,3}\.\d{1,6}[° ]?[EW]?\b'
IP_ADDRESS_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
MAC_PATTERN = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'

# Custom policy violations (e.g., do not share passwords)
POLICY_VIOLATIONS = ["password", "confidential", "internal use only", "secret", "proprietary"]
TRACKING_KEYWORDS = ["cookie", "tracking", "session"]
ACTIVITY_KEYWORDS = ["log", "activity", "history"]
SESSION_KEYWORDS = ["session_id", "token"]

# API 1: Extract text from an image
@app.route('/extract-text', methods=['POST'])
def extract_text():
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    # Read the image file
    image_file = request.files['image']
    image = Image.open(image_file)

    # Extract text using Tesseract OCR
    try:
        extracted_text = pytesseract.image_to_string(image)
        return jsonify({"text": extracted_text})
    except Exception as e:
        return jsonify({"error": f"Text extraction failed: {str(e)}"}), 500

def generate_alternative_text(text):
    """
    Generate alternative text by replacing sensitive information with synonyms or placeholders.
    """
    doc = nlp(text)
    matches = matcher(doc)
    sensitive_spans = [doc[start:end] for _, start, end in matches]

    # Replace sensitive entities detected by spaCy
    modified_text = text
    for span in sensitive_spans:
        if span.label_ == "PERSON":
            replacement = random.choice(name_synonyms)
        elif span.label_ == "GPE":
            replacement = random.choice(location_synonyms)
        elif span.text.replace("-", "").isdigit() and len(span.text) == 12:
            replacement = "[PHONE]"
        elif any(token.like_email for token in span):  # Check if any token in the span is an email
            replacement = "[EMAIL]"
        else:
            replacement = "[REDACTED]"
        modified_text = modified_text.replace(span.text, replacement)

    # Replace sensitive entities detected by regex
    modified_text = re.sub(email_regex, "[EMAIL]", modified_text)
    modified_text = re.sub(phone_regex, "[PHONE]", modified_text)
    modified_text = re.sub(ssn_regex, "[SSN]", modified_text)

    return modified_text

def generate_dynamic_response(violation_category, violation_text):
    """
    Generate a dynamic suggestion and reason based on the violation category and text.
    """
    if violation_category == "DATE":
        suggestion = f"Avoid sharing specific dates like '{violation_text}' or use a placeholder."
        reason = "This protects your privacy while still allowing you to share time-related information."
    elif violation_category == "GPE":
        suggestion = f"Avoid sharing specific locations like '{violation_text}' or use a placeholder."
        reason = "This protects your privacy while still allowing you to share location-related information."
    elif violation_category == "EMAIL":
        suggestion = f"Avoid sharing email addresses like '{violation_text}' or use a placeholder."
        reason = "This protects your email address from being misused or spammed."
    elif violation_category == "PHONE":
        suggestion = f"Avoid sharing phone numbers like '{violation_text}' or use a placeholder."
        reason = "This protects your phone number from being misused or contacted without consent."
    elif violation_category == "SSN":
        suggestion = f"Avoid sharing Social Security Numbers like '{violation_text}' or use a placeholder."
        reason = "This protects your Social Security Number from being misused for identity theft."
    elif violation_category == "API_KEY":
        suggestion = f"Avoid exposing API keys like '{violation_text}' in your code. Use environment variables instead."
        reason = "This keeps your API keys secure and prevents unauthorized access to your services."
    elif violation_category == "SOURCE_CODE":
        suggestion = f"Avoid sharing sensitive code like '{violation_text}'. Use pseudocode or redact specific details."
        reason = "This protects your intellectual property and prevents exposure of sensitive logic."
    elif violation_category == "COMPANY_INFO":
        suggestion = f"Avoid sharing company-specific information like '{violation_text}'. Use a placeholder instead."
        reason = "This protects your company's identity and prevents exposure of internal details."
    elif violation_category == "INTERNAL_INFRASTRUCTURE":
        suggestion = f"Avoid sharing details about internal infrastructure like '{violation_text}'. Use a generic term instead."
        reason = "This protects your organization's internal systems and prevents security risks."
    elif violation_category == "HEALTH_INFO":
        suggestion = f"Avoid sharing health-related information like '{violation_text}'. Use a placeholder instead."
        reason = "This protects your personal health information and ensures privacy."
    elif violation_category == "CREDIT_CARD":
        suggestion = f"Avoid sharing credit card numbers like '{violation_text}'. Use a placeholder instead."
        reason = "This protects your payment information and prevents financial fraud."
    elif violation_category == "IP_ADDRESS":
        suggestion = f"Avoid sharing IP addresses like '{violation_text}'. Use a placeholder instead."
        reason = "This protects your device information and prevents unauthorized access."
    elif violation_category == "MAC_ADDRESS":
        suggestion = f"Avoid sharing MAC addresses like '{violation_text}'. Use a placeholder instead."
        reason = "This protects your device information and prevents network-related risks."
    else:
        suggestion = "Remove the detected violation."
        reason = "This ensures no sensitive information is leaked."

    return suggestion, reason


# API 2: Detect violations in text
@app.route('/detect-violations', methods=['POST'])
def detect_violations():
    data = request.get_json()
    if 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data['text']
    violations = []

    # Detect PII and SPI using spaCy and regex
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "GPE", "DATE", "ORG"]:  # Add more spaCy labels if needed
            violations.append({"text": ent.text, "type": "PII", "category": ent.label_})

    # Detect emails, phone numbers, credit cards, SSNs, etc. using regex
    emails = re.findall(EMAIL_PATTERN, text)
    for email in emails:
        violations.append({"text": email, "type": "PII", "category": "EMAIL"})

    phones = re.findall(PHONE_PATTERN, text)
    for phone in phones:
        violations.append({"text": phone, "type": "PII", "category": "PHONE"})

    credit_cards = re.findall(CREDIT_CARD_PATTERN, text)
    for card in credit_cards:
        violations.append({"text": card, "type": "SPI", "category": "CREDIT_CARD"})

    ssns = re.findall(SSN_PATTERN, text)
    for ssn in ssns:
        violations.append({"text": ssn, "type": "SPI", "category": "SSN"})

    dobs = re.findall(DOB_PATTERN, text)
    for dob in dobs:
        violations.append({"text": dob, "type": "PII", "category": "DATE_OF_BIRTH"})

    passports = re.findall(PASSPORT_PATTERN, text)
    for passport in passports:
        violations.append({"text": passport, "type": "PII", "category": "PASSPORT"})

    drivers_licenses = re.findall(DRIVERS_LICENSE_PATTERN, text)
    for dl in drivers_licenses:
        violations.append({"text": dl, "type": "PII", "category": "DRIVERS_LICENSE"})

    bank_accounts = re.findall(BANK_ACCOUNT_PATTERN, text)
    for account in bank_accounts:
        violations.append({"text": account, "type": "SPI", "category": "BANK_ACCOUNT"})

    health_info = re.findall(HEALTH_PATTERN, text, re.IGNORECASE)
    for info in health_info:
        violations.append({"text": info, "type": "SPI", "category": "HEALTH_INFO"})

    insurance_info = re.findall(INSURANCE_PATTERN, text)
    for info in insurance_info:
        violations.append({"text": info, "type": "SPI", "category": "INSURANCE"})

    biometric_data = re.findall(BIOMETRIC_PATTERN, text, re.IGNORECASE)
    for data in biometric_data:
        violations.append({"text": data, "type": "SPI", "category": "BIOMETRIC_DATA"})

    genetic_data = re.findall(GENETIC_PATTERN, text, re.IGNORECASE)
    for data in genetic_data:
        violations.append({"text": data, "type": "SPI", "category": "GENETIC_DATA"})

    gps_coords = re.findall(GPS_PATTERN, text)
    for coord in gps_coords:
        violations.append({"text": coord, "type": "CONTEXTUAL", "category": "GPS_COORDINATES"})

    ip_addresses = re.findall(IP_ADDRESS_PATTERN, text)
    for ip in ip_addresses:
        violations.append({"text": ip, "type": "CONTEXTUAL", "category": "IP_ADDRESS"})

    mac_addresses = re.findall(MAC_PATTERN, text)
    for mac in mac_addresses:
        violations.append({"text": mac, "type": "CONTEXTUAL", "category": "MAC_ADDRESS"})

    # Detect policy violations using custom keywords
    for keyword in POLICY_VIOLATIONS:
        if keyword.lower() in text.lower():
            violations.append({"text": keyword, "type": "POLICY_VIOLATION", "category": "CUSTOM_KEYWORD"})

    # Detect tracking-related keywords
    for keyword in TRACKING_KEYWORDS:
        if keyword.lower() in text.lower():
            violations.append({"text": keyword, "type": "BEHAVIORAL", "category": "TRACKING"})

    # Detect activity-related keywords
    for keyword in ACTIVITY_KEYWORDS:
        if keyword.lower() in text.lower():
            violations.append({"text": keyword, "type": "BEHAVIORAL", "category": "ACTIVITY_LOG"})

    # Detect session-related keywords
    for keyword in SESSION_KEYWORDS:
        if keyword.lower() in text.lower():
            violations.append({"text": keyword, "type": "BEHAVIORAL", "category": "SESSION_ID"})

    return jsonify({"violations": violations})

# API 3: Suggest solutions for detected violations
@app.route('/suggest-solutions', methods=['POST'])
def suggest_solutions():
    data = request.get_json()
    if 'violations' not in data:
        return jsonify({"error": "No violations provided"}), 400

    violations = data['violations']
    recommendations = []

    for violation in violations:
        violation_type = violation['type']
        violation_text = violation['text']
        violation_category = violation['category']

        # Generate alternative text using spaCy and regex
        alternative_text = generate_alternative_text(violation_text)

        # Generate dynamic suggestion and reason
        suggestion, reason = generate_dynamic_response(violation_category, violation_text)

        recommendations.append({
            "action": "Generalize",
            "original": violation_text,
            "suggestion": suggestion,
            "example": alternative_text,
            "reason": reason
        })

    return jsonify({"recommendations": recommendations})


# Swagger configuration
SWAGGER_URL = "/swagger"  # URL for accessing the Swagger UI
API_URL = "/swagger.json"  # URL for the Swagger JSON file

# Create the Swagger UI blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={"app_name": "Text Extraction API"}
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route("/swagger.json")
def swagger():
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "Privacy Protection API",
            "version": "1.0.0",
            "description": "API for detecting and addressing privacy violations in text and images."
        },
        "paths": {
            "/extract-text": {
                "post": {
                    "summary": "Extract text from an image",
                    "description": "Upload an image file to extract and retrieve the text content.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "image": {
                                            "type": "string",
                                            "format": "binary",
                                            "description": "The image file to process (supported formats: PNG, JPG, JPEG)."
                                        }
                                    },
                                    "required": ["image"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Text extracted successfully.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "text": {
                                                "type": "string",
                                                "description": "The extracted text from the image."
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid request due to missing or incorrect input.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "error": {
                                                "type": "string",
                                                "description": "Details about the error, e.g., 'No image file provided.'"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "500": {
                            "description": "An error occurred during text extraction.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "error": {
                                                "type": "string",
                                                "description": "Technical details about the issue, e.g., 'Failed to process the image file.'"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/detect-violations": {
                "post": {
                    "summary": "Identify privacy violations in text",
                    "description": "Analyze the input text to detect potential privacy violations, such as Personally Identifiable Information (PII).",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "text": {
                                            "type": "string",
                                            "description": "The text to analyze for privacy violations."
                                        }
                                    },
                                    "required": ["text"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Privacy violations detected successfully.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "violations": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "text": {
                                                            "type": "string",
                                                            "description": "The specific text identified as a violation."
                                                        },
                                                        "type": {
                                                            "type": "string",
                                                            "description": "The type of violation (e.g., PII, sensitive information)."
                                                        },
                                                        "category": {
                                                            "type": "string",
                                                            "description": "The category of violation (e.g., EMAIL, PHONE, SSN)."
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid input provided.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "error": {
                                                "type": "string",
                                                "description": "Details about the error, e.g., 'No text provided for analysis.'"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/suggest-solutions": {
                "post": {
                    "summary": "Provide recommendations for resolving privacy violations",
                    "description": "Suggest actionable solutions to address detected privacy violations.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "violations": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "text": {
                                                        "type": "string",
                                                        "description": "The text identified as a violation."
                                                    },
                                                    "type": {
                                                        "type": "string",
                                                        "description": "The type of violation (e.g., PII, sensitive information)."
                                                    },
                                                    "category": {
                                                        "type": "string",
                                                        "description": "The category of violation (e.g., EMAIL, PHONE, SSN)."
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    "required": ["violations"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Recommendations provided successfully.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "recommendations": {
                                                "type": "array",
                                                "items": {
                                                    "type": "string",
                                                    "description": "A recommendation for resolving a specific violation."
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid input provided.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "error": {
                                                "type": "string",
                                                "description": "Details about the error, e.g., 'No violations provided for resolution.'"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })

if __name__ == '__main__':
    port = int(os.getenv("PORT", 4444))
    app.run(host='0.0.0.0', port=port, debug=False)
