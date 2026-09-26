import typer
from rich.console import Console
from rich.table import Table

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

    # ==========================================================
    # SUMMARY
    # ==========================================================

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
        f"Endpoints discovered: "
        f"[yellow]{len(results['endpoint_inventory'])}[/yellow]"
    )

    # ==========================================================
    # ENDPOINT INVENTORY
    # ==========================================================

    console.print(
        "\n[bold cyan]Endpoint Inventory[/bold cyan]\n"
    )

    endpoint_table = Table(
        show_header=True,
        header_style="bold",
    )

    endpoint_table.add_column(
        "Method",
        style="cyan",
        width=8,
    )

    endpoint_table.add_column(
        "Path",
        style="white",
        min_width=30,
    )

    endpoint_table.add_column(
        "Type",
        style="yellow",
        width=10,
    )

    endpoint_table.add_column(
        "Parameters",
        style="green",
    )

    endpoint_table.add_column(
        "Sources",
        style="magenta",
    )

    endpoint_inventory = (
        results["endpoint_inventory"]
    )

    for endpoint_key in sorted(
        endpoint_inventory
    ):

        endpoint = endpoint_inventory[
            endpoint_key
        ]

        parameters = endpoint.get(
            "parameters",
            [],
        )

        sources = endpoint.get(
            "sources",
            [],
        )

        endpoint_table.add_row(
            endpoint.get(
                "method",
                "GET",
            ),
            endpoint.get(
                "path",
                "/",
            ),
            endpoint.get(
                "type",
                "OTHER",
            ),
            ", ".join(
                parameters
            ) or "-",
            ", ".join(
                sources
            ) or "-",
        )

    console.print(
        endpoint_table
    )

    # ==========================================================
    # API ENDPOINTS
    # ==========================================================

    api_endpoints = [
        endpoint
        for endpoint in endpoint_inventory.values()
        if endpoint.get("type") == "API"
    ]

    console.print(
        "\n[bold cyan]API Endpoints[/bold cyan]\n"
    )

    if api_endpoints:

        api_table = Table(
            show_header=True,
            header_style="bold",
        )

        api_table.add_column(
            "Method",
            style="cyan",
            width=8,
        )

        api_table.add_column(
            "Endpoint",
            style="white",
        )

        api_table.add_column(
            "Parameters",
            style="green",
        )

        for endpoint in sorted(
            api_endpoints,
            key=lambda item: (
                item.get("method", "GET"),
                item.get("path", "/"),
            ),
        ):

            api_table.add_row(
                endpoint.get(
                    "method",
                    "GET",
                ),
                endpoint.get(
                    "path",
                    "/",
                ),
                ", ".join(
                    endpoint.get(
                        "parameters",
                        [],
                    )
                ) or "-",
            )

        console.print(
            api_table
        )

    else:

        console.print(
            "[dim]No API endpoints discovered.[/dim]"
        )

    # ==========================================================
    # SOCKET ENDPOINTS
    # ==========================================================

    socket_endpoints = [
        endpoint
        for endpoint in endpoint_inventory.values()
        if endpoint.get("type") == "SOCKET"
    ]

    console.print(
        "\n[bold cyan]Socket Endpoints[/bold cyan]\n"
    )

    if socket_endpoints:

        for endpoint in sorted(
            socket_endpoints,
            key=lambda item: item.get(
                "path",
                "/",
            ),
        ):

            console.print(
                f"  [yellow]"
                f"{endpoint.get('method', 'GET')}"
                f"[/yellow] "
                f"{endpoint.get('path', '/')}"
            )

    else:

        console.print(
            "[dim]No socket endpoints discovered.[/dim]"
        )

    # ==========================================================
    # PARAMETERS
    # ==========================================================

    console.print(
        "\n[bold cyan]Parameters[/bold cyan]"
    )

    if results["parameters"]:

        for parameter in sorted(
            results["parameters"]
        ):

            console.print(
                f"  {parameter}"
            )

    else:

        console.print(
            "  [dim]No parameters discovered.[/dim]"
        )

    # ==========================================================
    # FORMS
    # ==========================================================

    console.print(
        "\n[bold cyan]Forms[/bold cyan]"
    )

    if results["forms"]:

        for form in results["forms"]:

            console.print(
                f"\n  Page:   "
                f"{form['page']}"
            )

            console.print(
                f"  Action: "
                f"{form['action']}"
            )

            console.print(
                f"  Method: "
                f"{form['method']}"
            )

            for input_field in form[
                "inputs"
            ]:

                console.print(
                    f"    - "
                    f"{input_field['name']} "
                    f"({input_field['type']})"
                )

    else:

        console.print(
            "  [dim]No forms discovered.[/dim]"
        )

    # ==========================================================
    # STATIC RESOURCES
    # ==========================================================

    static_endpoints = [
        endpoint
        for endpoint in endpoint_inventory.values()
        if endpoint.get("type") == "STATIC"
    ]

    console.print(
        "\n[bold cyan]Static Resources[/bold cyan]\n"
    )

    if static_endpoints:

        console.print(
            f"  Discovered: "
            f"[yellow]{len(static_endpoints)}[/yellow]"
        )

        for endpoint in sorted(
            static_endpoints,
            key=lambda item: item.get(
                "path",
                "/",
            ),
        ):

            console.print(
                f"  {endpoint.get('path', '/')}"
            )

    else:

        console.print(
            "  [dim]No static resources discovered.[/dim]"
        )


if __name__ == "__main__":
    app()