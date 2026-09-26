import typer
from rich.console import Console

from vulnai.core.http_client import HTTPClient
from vulnai.crawler.crawler import Crawler


app = typer.Typer(
    name="vulnai",
    help="AI-assisted web vulnerability assessment platform."
)

console = Console()


@app.command()
def version():
    """Show VulnAI version."""

    console.print(
        "[bold green]VulnAI[/bold green] v0.1.0"
    )


@app.command()
def hello():
    """Test the VulnAI CLI."""

    console.print(
        "[bold cyan]VulnAI scanner is ready.[/bold cyan]"
    )


@app.command()
def request(url: str):
    """Send a basic HTTP GET request."""

    client = HTTPClient()

    try:

        response = client.get(url)

        console.print(
            f"[green]Status:[/green] "
            f"{response.status_code}"
        )

        console.print(
            f"[green]Final URL:[/green] "
            f"{response.url}"
        )

        console.print(
            f"[green]Content-Type:[/green] "
            f"{response.headers.get('content-type', 'unknown')}"
        )

        console.print(
            f"[green]Response Size:[/green] "
            f"{len(response.content)} bytes"
        )

    except Exception as error:

        console.print(
            f"[red]Request failed:[/red] "
            f"{error}"
        )


@app.command()
def crawl(
    url: str,
    depth: int = typer.Option(
        2,
        "--depth",
        "-d",
        help="Maximum crawl depth."
    ),
):
    """Crawl an authorized web application."""

    console.print(
        "\n[bold cyan]VulnAI Crawler[/bold cyan]"
    )

    console.print(
        f"[green]Target:[/green] {url}"
    )

    console.print(
        f"[green]Depth:[/green] {depth}\n"
    )

    crawler = Crawler(
        start_url=url,
        max_depth=depth,
    )

    try:

        results = crawler.crawl()

    except Exception as error:

        console.print(
            f"[red]Crawler failed:[/red] "
            f"{error}"
        )

        return

    console.print(
        "\n[bold green]Crawl completed[/bold green]"
    )

    console.print(
        f"\nURLs found: "
        f"[yellow]{len(results['urls'])}[/yellow]"
    )

    console.print(
        f"Forms found: "
        f"[yellow]{len(results['forms'])}[/yellow]"
    )

    console.print(
        f"Parameters found: "
        f"[yellow]{len(results['parameters'])}[/yellow]"
    )

    console.print(
        f"API requests found: "
        f"[yellow]{len(results['api_requests'])}[/yellow]"
    )

    console.print(
        "\n[bold]URLs:[/bold]"
    )

    for discovered_url in sorted(
        results["urls"]
    ):

        console.print(
            f"  {discovered_url}"
        )

    console.print(
        "\n[bold]Parameters:[/bold]"
    )

    for parameter in sorted(
        results["parameters"]
    ):

        console.print(
            f"  {parameter}"
        )

    console.print(
        "\n[bold]API Requests:[/bold]"
    )

    for api_url in sorted(
        results["api_requests"]
    ):

        console.print(
            f"  {api_url}"
        )

    console.print(
        "\n[bold]Forms:[/bold]"
    )

    for form in results["forms"]:

        console.print(
            f"\n  Page:   {form['page']}"
        )

        console.print(
            f"  Action: {form['action']}"
        )

        console.print(
            f"  Method: {form['method']}"
        )

        for input_field in form["inputs"]:

            console.print(
                f"    - {input_field['name']} "
                f"({input_field['type']})"
            )


if __name__ == "__main__":
    app()