rule Triage_Synthetic_Marker
{
    meta:
        description = "Harmless marker that make_corpus.py plants in every 'bad' file"
        expected = "hits every bad file, no false positives"

    strings:
        $marker = "TRIAGE-SYNTHETIC-MARKER-7f3a" ascii wide

    condition:
        $marker
}
