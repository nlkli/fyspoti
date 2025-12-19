use serde::Deserialize;

#[derive(Deserialize, Default, Debug)]
pub struct ApResolveData {
    pub accesspoint: Vec<String>,
    // pub dealer: Vec<String>,
    // pub spclient: Vec<String>,
}

impl ApResolveData {
    pub fn accesspoint_4070(&self) -> impl Iterator<Item = &String> {
        self.accesspoint
            .iter()
            .filter(|s| s.ends_with(":4070"))
    }
}

pub async fn reqwest_ap_resolve_data() -> Result<ApResolveData, Box<dyn std::error::Error>> {
    let body = reqwest::get("https://apresolve.spotify.com/?type=accesspoint&type=dealer&type=spclient")
        .await?
        .bytes()
        .await?;
    Ok(serde_json::from_slice(&body)?)
}
