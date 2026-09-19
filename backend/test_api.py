from starlette.testclient import TestClient
from main import app
import json

client = TestClient(app)

def test_investigate_and_challenge():
    # Test evidence
    evidence = {
        "type": "text",
        "content": "URGENT: Your account will be suspended! Click http://paypa1.com-security.net to verify your information immediately or lose access forever. This is a final notice from authority."
    }

    # Post to /investigate
    response = client.post("/investigate", json=evidence)
    print(f"Investigate response status: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    investigate_result = response.json()
    case_id = investigate_result["case_id"]

    # Check that case_id is in the format TRC-XXXXXXXX
    assert case_id.startswith("TRC-"), f"Case ID {case_id} does not start with TRC-"
    assert len(case_id) == 12, f"Case ID {case_id} length is not 12"

    # Check that the investigation was stored in memory
    assert case_id in investigation_store, f"Case ID {case_id} not found in investigation_store"

    # Post to /investigate/{case_id}/challenge
    challenge_response = client.post(f"/investigate/{case_id}/challenge")
    print(f"Challenge response status: {challenge_response.status_code}")
    assert challenge_response.status_code == 200, f"Expected 200, got {challenge_response.status_code}"

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
    # We expect at least one challenge (though it could be empty if Devil's Advocate has nothing to say)
    # But given the evidence, we expect some challenges.
    # We'll just check that it's a list.

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

    # Additionally, we can check that the revised_verdict is different from previous_verdict or not
    # but we don't require it to be different.

    return True

if __name__ == "__main__":
    try:
        test_investigate_and_challenge()
        print("Test passed!")
    except Exception as e:
        print(f"Test failed: {e}")
        raise
