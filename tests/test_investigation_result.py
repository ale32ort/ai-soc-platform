from models.investigation_result import InvestigationResult


def main():

    result = InvestigationResult(
        verdict="Likely Benign",
        confidence=95,
        summary="McAfee Dynamic Application Downloader service appears legitimate.",
        reasoning=[
            "Executable is located under Program Files.",
            "Service name matches McAfee software.",
        ],
        mitre_techniques=[
            "T1543.003",
        ],
        recommendations=[
            "No action required.",
        ],
    )

    print(result.pretty_print())


if __name__ == "__main__":
    main()
