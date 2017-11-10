from catch_phishing import score_domain


def test_score_domain():
    """Unit test score_domain function from catch_physhing script."""

    # Suspicious domains
    assert score_domain('www.paypal.xit') > 75
    assert score_domain('paypal-datacenter.com-account-alert.com') > 75

    # Clean domains
    assert score_domain('www.google.com') < 50
