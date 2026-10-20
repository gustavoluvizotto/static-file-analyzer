rule Triage_Noisy_Any_URL
{
    meta:
        description = "Deliberately noisy: fires on any http(s) URL"
        expected = "false positives on good/notes.txt and good/install.sh"

    strings:
        $http = "http://" nocase ascii wide
        $https = "https://" nocase ascii wide

    condition:
        any of them
}
