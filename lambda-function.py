import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta

import requests
from flask import Flask, request, jsonify, redirect
import jwt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# GitHub App settings
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.environ.get("GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")
GITHUB_APP_NAME = os.environ.get("GITHUB_APP_NAME", "code-review-assistant")

# API endpoints
GITHUB_API = "https://api.github.com"

def generate_jwt():
    """Generate a JWT for GitHub App authentication"""
    now = datetime.utcnow()
    payload = {
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "iss": GITHUB_APP_ID
    }
    
    token = jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm="RS256")
    return token

def get_installation_token(installation_id):
    """Get an installation access token for a specific installation"""
    jwt_token = generate_jwt()
    
    url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    response = requests.post(url, headers=headers)
    response.raise_for_status()
    
    return response.json()["token"]

def verify_webhook_signature(request_data, signature_header):
    """Verify the webhook signature from GitHub"""
    if not signature_header:
        return False
        
    signature = signature_header.split("=")[1]
    
    mac = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        msg=request_data,
        digestmod=hashlib.sha256
    )
    
    return hmac.compare_digest(mac.hexdigest(), signature)

@app.route("/webhook", methods=["POST"])
def webhook():
    """Webhook endpoint for GitHub events"""
    # Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_webhook_signature(request.data, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401
    
    event_type = request.headers.get("X-GitHub-Event")
    payload = request.json
    
    logger.info(f"Received {event_type} event")
    
    # Handle different event types
    if event_type == "pull_request":
        handle_pull_request(payload)
    elif event_type == "pull_request_review_comment":
        handle_pr_review_comment(payload)
    elif event_type == "push":
        handle_push(payload)
    
    return jsonify({"status": "Processing"}), 202

def handle_pull_request(payload):
    """Handle pull request events"""
    # Only process opened or synchronized PRs
    if payload["action"] not in ["opened", "synchronize"]:
        return
    
    installation_id = payload["installation"]["id"]
    repo_name = payload["repository"]["name"]
    repo_owner = payload["repository"]["owner"]["login"]
    pr_number = payload["pull_request"]["number"]
    
    logger.info(f"Processing PR #{pr_number} in {repo_owner}/{repo_name}")
    
    # Get installation token
    token = get_installation_token(installation_id)
    
    # Get PR files
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    pr_files_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files"
    response = requests.get(pr_files_url, headers=headers)
    response.raise_for_status()
    
    files = response.json()
    
    # Analyze code and add comments
    analyze_and_comment_on_pr(token, repo_owner, repo_name, pr_number, files, payload["pull_request"]["head"]["sha"])

def handle_pr_review_comment(payload):
    """Handle PR review comment events"""
    # Check if the comment mentions @Jarvis
    if "@Jarvis" in payload["comment"]["body"]:
        installation_id = payload["installation"]["id"]
        repo_name = payload["repository"]["name"]
        repo_owner = payload["repository"]["owner"]["login"]
        pr_number = payload["pull_request"]["number"]
        comment_id = payload["comment"]["id"]
        
        # Get installation token
        token = get_installation_token(installation_id)
        
        # Process Jarvis command and respond
        process_jarvis_command(token, repo_owner, repo_name, pr_number, comment_id, payload["comment"]["body"])

def handle_push(payload):
    """Handle push events"""
    # Process push events if needed
    # For now, we'll focus on PR automation
    pass

def analyze_and_comment_on_pr(token, repo_owner, repo_name, pr_number, files, commit_sha):
    """Analyze code in PR and add review comments"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Initialize review comments
    review_comments = []
    
    # Process each file
    for file in files:
        filename = file["filename"]
        file_extension = os.path.splitext(filename)[1]
        
        # Skip binary files, images, etc.
        if file_extension.lower() not in ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs']:
            continue
            
        # Get file content
        if file["status"] != "removed":
            content_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/contents/{filename}?ref={commit_sha}"
            response = requests.get(content_url, headers=headers)
            
            if response.status_code == 200:
                content_data = response.json()
                content = base64_decode(content_data["content"])
                
                # Analyze the code
                issues = analyze_code(content, filename)
                
                # Add review comments for each issue
                for issue in issues:
                    review_comments.append({
                        "path": filename,
                        "position": issue["line"],
                        "body": format_review_comment(issue),
                        "commit_id": commit_sha
                    })
    
    # Submit review if there are comments
    if review_comments:
        review_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/reviews"
        review_data = {
            "commit_id": commit_sha,
            "body": "I've reviewed your code and found some potential issues.",
            "event": "COMMENT",
            "comments": review_comments
        }
        
        response = requests.post(review_url, headers=headers, json=review_data)
        if response.status_code in [200, 201]:
            logger.info(f"Added {len(review_comments)} review comments to PR #{pr_number}")
        else:
            logger.error(f"Failed to add review: {response.status_code} - {response.text}")

def analyze_code(content, filename):
    """
    Analyze code for potential issues
    Returns a list of issues with line numbers and descriptions
    """
    # This is a placeholder - in a real implementation, you would:
    # 1. Use static analysis tools
    # 2. Call AI services
    # 3. Apply custom rules
    
    # For now, we'll return some mock issues
    issues = []
    
    lines = content.split("\n")
    for i, line in enumerate(lines):
        # Check for long lines
        if len(line) > 100:
            issues.append({
                "line": i + 1,
                "type": "style",
                "message": "Line is too long (over 100 characters)",
                "severity": "low"
            })
        
        # Check for print statements in Python files
        if filename.endswith(".py") and "print(" in line:
            issues.append({
                "line": i + 1,
                "type": "best_practice",
                "message": "Consider using logging instead of print statements in production code",
                "severity": "medium"
            })
            
    return issues

def process_jarvis_command(token, repo_owner, repo_name, pr_number, comment_id, comment_body):
    """Process a command directed at the @Jarvis assistant"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Extract the command after @Jarvis
    command = comment_body.split("@Jarvis", 1)[1].strip()
    
    if "suggest prompt" in command.lower():
        # Generate a review prompt suggestion
        suggestion = "Here's a suggested prompt for review:\n\n" + \
                    "Please review this code focusing on:\n" + \
                    "- Code efficiency\n" + \
                    "- Adherence to best practices\n" + \
                    "- Potential edge cases\n" + \
                    "- Test coverage"
    else:
        # Default response
        suggestion = "I'm here to help! You can ask me to suggest prompts or analyze specific aspects of the code."
    
    # Reply to the comment
    reply_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/issues/comments/{comment_id}/replies"
    response = requests.post(reply_url, headers=headers, json={"body": suggestion})
    
    if response.status_code not in [201, 200]:
        # If the above endpoint fails (it's relatively new), fall back to a regular comment
        comment_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments"
        requests.post(comment_url, headers=headers, json={
            "body": f"**@Jarvis response**\n\n{suggestion}"
        })

def base64_decode(content):
    """Decode base64 content from GitHub API"""
    import base64
    return base64.b64decode(content).decode('utf-8')

def format_review_comment(issue):
    """Format an issue as a review comment"""
    severity_emoji = {
        "high": "🔴",
        "medium": "🟡",
        "low": "🟢"
    }
    
    emoji = severity_emoji.get(issue["severity"], "ℹ️")
    
    return f"{emoji} **{issue['type'].replace('_', ' ').title()}**\n\n{issue['message']}"

@app.route("/setup", methods=["GET"])
def setup():
    """Redirect to GitHub App installation page"""
    return redirect(f"https://github.com/apps/{GITHUB_APP_NAME}/installations/new")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
