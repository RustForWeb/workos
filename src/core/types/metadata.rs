use std::collections::HashMap;

use derive_more::From;
use serde::{Deserialize, Serialize};

/// The metadata key/value paris associated with an object.
#[derive(Clone, Debug, From, PartialEq, Eq, Serialize, Deserialize)]
#[from(forward)]
pub struct Metadata(pub HashMap<String, String>);

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use serde_json::json;

    use super::Metadata;

    #[test]
    fn it_deserializes_metadata() {
        let metadata: Metadata = serde_json::from_str(
            &json!({
                "key": "value",
            })
            .to_string(),
        )
        .unwrap();

        let expected_metadata = HashMap::from([("key".to_string(), "value".to_string())]);

        assert_eq!(metadata, Metadata(expected_metadata))
    }
}
