from ml.feature_engineering import FEATURE_NAMES, extract_features


def test_feature_vector_has_expected_length():
    features = extract_features("' UNION SELECT username FROM users -- ")
    assert len(features) == len(FEATURE_NAMES)


def test_sql_keywords_increase_keyword_feature():
    benign = extract_features("alice")
    malicious = extract_features("' UNION SELECT username FROM users -- ")
    keyword_index = FEATURE_NAMES.index("sql_keyword_hits")
    assert malicious[keyword_index] > benign[keyword_index]
