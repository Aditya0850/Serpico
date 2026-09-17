import requests
import json

BASE_URL = "http://localhost:8000"

def test_investigate_and_challenge():
    # Test evidence
    evidence = {
        "type": "text",
        "content": "URGENT: Your account will be suspended! Click http://paypa1.com-security.net to verify your information immediately or lose access forever. This is a final notice from authority."
    }
    
    # Post to /investigate
    response = requests.post(f"{BASE_URL}/investigate", json=evidence)
    print(f"Investigate response status: {response.status_code}")
    if response.status_code != 200:
        print(f"Response: {response.text}")
        raise Exception(f"Expected 200, got {response.status_code}")
    
    investigate_result = response.json()
    case_id = investigate_result["case_id"]
    print(f"Case ID: {case_id}")
    
    # Check that case_id is in the format TRC-XXXXXXXX
    assert case_id.startswith("TRC-"), f"Case ID {case_id} does not start with TRC-"
    assert len(case_id) == 12, f"Case ID {case_id} length is not 12"
    
    # Post to /investigate/{case_id}/challenge
    challenge_response = requests.post(f"{BASE_URL}/investigate/{case_id}/challenge")
    print(f"Challenge response status: {challenge_response.status_code}")
    if challenge_response.status_code != 200:
        print(f"Response: {challenge_response.text}")
        raise Exception(f"Expected 200, got {challenge_response.status_code}")
    
    challenge_result = challenge_response.json()
    print(f"Challenge result keys: {challenge_result.keys()}")
    
    # Verify the response contains the required fields
    assert "case_id" in challenge_result
    assert "previous_verdict" in challenge_result
    assert "new_challenges" in challenge_result
    assert "revised_verdict" in challenge_result
    assert "what_changed" in challenge_result
    
    # Verify case_id matches
    assert challenge_result["case_id"] == case_id
    
    # Verify that new_challenges is a list
    assert isinstance(challenge_result["new_challenges"], list)
    
    # Verify that previous_verdict and revised_verdict are dicts with risk_level and confidence
    assert "risk_level" in challenge_result["previous_verdict"]
    assert "confidence" in challenge_result["previous_verdict"]
    assert "risk_level" in challenge_result["revised_verdict"]
    assert "confidence" in challenge_result["revised_verdict"]
    
    # Verify that what_changed is a list of strings
    assert isinstance(challenge_result["what_changed"], list)
    for item in challenge_result["what_changed"]:
        assert isinstance(item, str)
    
    print("All assertions passed!")
    
    return True

if __name__ == "__main__":
    try:
        test_investigate_and_challenge()
        print("Test passed!")
    except Exception as e:
        print(f"Test failed: {e}")
        raise
