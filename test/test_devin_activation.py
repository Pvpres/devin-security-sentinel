import os
import requests
import json


DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
TARGET_REPO = "pvpres/small_scale_security_tests"

url = "https://api.devin.ai/v1/sessions"

payload = {
    "prompt": f"List all the files and security vulnerabilities in the repository.{TARGET_REPO}",
}
def test_devin_activation():
    headers = {"Authorization": f"Bearer {DEVIN_API_KEY}", "Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json=payload)
    assert response.status_code == 200
    print("Devin activation test passed.")
    print(response.text)

if __name__ == "__main__":
    print("Running Devin activation test...")
    test_devin_activation()