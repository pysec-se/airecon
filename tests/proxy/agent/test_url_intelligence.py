"""Tests for url_intelligence.py — URL classification, directory extraction, smart filtering."""

from __future__ import annotations

from airecon.proxy.agent.url_intelligence import (
    classify_url,
    extract_parent_directory,
    filter_static_assets,
    has_path_parameters,
    has_query_parameters,
    is_endpoint_worth_testing,
    sort_urls_by_priority,
)


class TestExtractParentDirectory:
    def test_css_file_directory(self):
        d = extract_parent_directory("https://example.com/path/file.css")
        assert d == "https://example.com/path/"

    def test_png_file_directory(self):
        d = extract_parent_directory("https://example.com/assets/images/logo.png")
        assert d == "https://example.com/assets/images/"

    def test_deep_path_directory(self):
        d = extract_parent_directory("https://example.com/a/b/c/d.jpg")
        assert d == "https://example.com/a/b/c/"

    def test_root_has_no_parent(self):
        # Even root paths have a directory (the root /)
        d = extract_parent_directory("https://example.com/favicon.ico")
        assert d == "https://example.com/"

    def test_no_extension_still_works(self):
        d = extract_parent_directory("https://example.com/api/v1/users")
        assert d == "https://example.com/api/v1/"


class TestClassifyUrl:
    def test_pure_static_css(self):
        c = classify_url("https://example.com/assets/style.css")
        assert c["is_pure_static"] is True
        assert c["is_testable"] is False
        assert c["is_informational"] is False
        assert c["extension"] == "css"
        assert c["directory_url"] == "https://example.com/assets/"

    def test_pure_static_png(self):
        c = classify_url("https://example.com/images/logo.png")
        assert c["is_pure_static"] is True
        assert c["directory_url"] is not None

    def test_pure_static_woff(self):
        c = classify_url("https://example.com/fonts/roboto.woff2")
        assert c["is_pure_static"] is True

    def test_pure_static_ico(self):
        c = classify_url("https://example.com/favicon.ico")
        assert c["is_pure_static"] is True

    def test_js_file_is_gold(self):
        c = classify_url("https://example.com/js/app.js")
        assert c["category"] == "js_file"
        assert c["is_pure_static"] is False
        assert c["is_informational"] is True
        assert c["guidance"] is not None  # JS analysis tips
        assert c["directory_url"] is not None

    def test_typescript_file(self):
        c = classify_url("https://example.com/dist/bundle.ts")
        assert c["category"] == "js_file"
        assert c["is_pure_static"] is False

    def test_jsx_file(self):
        c = classify_url("https://example.com/src/App.jsx")
        assert c["category"] == "js_file"

    def test_pdf_is_informational_not_static(self):
        c = classify_url("https://example.com/docs/internal-report.pdf")
        assert c["is_informational"] is True
        assert c["is_pure_static"] is False
        assert c["category"] == "informational"

    def test_docx_is_informational(self):
        c = classify_url("https://example.com/files/credentials.xlsx")
        assert c["is_informational"] is True
        assert c["is_pure_static"] is False

    def test_source_map_reveals_code(self):
        c = classify_url("https://example.com/js/app.js.map")
        assert c["is_informational"] is True
        assert c["priority"] >= 50  # High — reveals source code

    def test_api_endpoint(self):
        c = classify_url("https://example.com/api/v1/users")
        assert c["is_testable"] is True
        assert c["is_pure_static"] is False
        assert c["priority"] >= 80

    def test_graphql_endpoint(self):
        c = classify_url("https://example.com/graphql")
        assert c["is_testable"] is True
        assert c["priority"] >= 80

    def test_url_with_query_params(self):
        c = classify_url("https://example.com/search?q=test&page=1")
        assert c["is_testable"] is True
        assert c["has_query_params"] is True
        assert "q" in c["param_names"]
        assert "page" in c["param_names"]

    def test_url_with_path_param(self):
        c = classify_url("https://example.com/api/users/12345")
        assert c["is_testable"] is True
        assert c["has_path_params"] is True

    def test_url_with_brace_param(self):
        c = classify_url("https://example.com/api/users/{id}")
        assert c["has_path_params"] is True

    def test_url_with_colon_param(self):
        c = classify_url("https://example.com/api/users/:id")
        assert c["has_path_params"] is True

    def test_login_page(self):
        c = classify_url("https://example.com/login")
        assert c["is_testable"] is True

    def test_admin_panel(self):
        c = classify_url("https://example.com/admin/dashboard")
        assert c["is_testable"] is True

    def test_upload_endpoint(self):
        c = classify_url("https://example.com/api/upload")
        assert c["is_testable"] is True

    def test_html_page_is_testable(self):
        c = classify_url("https://example.com/about.html")
        assert c["is_pure_static"] is False
        # HTML could have SSTI
        assert c["is_testable"] is True

    def test_php_is_testable(self):
        c = classify_url("https://example.com/index.php")
        assert c["is_testable"] is True

    def test_static_css_has_low_priority(self):
        c = classify_url("https://example.com/style.css")
        assert c["is_pure_static"] is True
        assert c["priority"] <= 40  # Low but dir fuzzing possible


class TestFilterStaticAssets:
    def test_three_way_split(self):
        urls = [
            "https://example.com/api/v1/users",       # testable
            "https://example.com/assets/style.css",   # pure static
            "https://example.com/images/logo.png",    # pure static
            "https://example.com/js/app.js",          # js_file (informational)
            "https://example.com/docs/report.pdf",    # informational
            "https://example.com/search?q=test",      # testable
        ]
        testable, informational, pure_static = filter_static_assets(urls)

        # testable: api endpoint, search with params
        assert len(testable) >= 2
        # informational: JS, PDF
        assert len(informational) >= 2
        # pure static: css, png
        assert len(pure_static) >= 2

    def test_all_pure_static(self):
        urls = [
            "https://example.com/a.css",
            "https://example.com/b.png",
            "https://example.com/c.jpg",
        ]
        testable, informational, pure_static = filter_static_assets(urls)
        assert len(testable) == 0
        assert len(informational) == 0
        assert len(pure_static) == 3

    def test_all_testable(self):
        urls = [
            "https://example.com/api/users",
            "https://example.com/graphql",
            "https://example.com/login",
        ]
        testable, informational, pure_static = filter_static_assets(urls)
        assert len(testable) == 3
        assert len(informational) == 0
        assert len(pure_static) == 0

    def test_js_not_in_static(self):
        urls = [
            "https://example.com/js/app.js",
            "https://example.com/js/vendor.js",
        ]
        testable, informational, pure_static = filter_static_assets(urls)
        # JS should be informational, NOT pure static
        assert len(pure_static) == 0
        assert len(informational) == 2


class TestSortUrlsByPriority:
    def test_sorting_order(self):
        urls = [
            "https://example.com/assets/style.css",   # priority 40 (dir fuzzable)
            "https://example.com/api/v1/users",       # priority 85+
            "https://example.com/graphql",            # priority 85+
            "https://example.com/about",              # priority 30 (unknown, no pattern)
        ]
        sorted_urls = sort_urls_by_priority(urls)
        # API and GraphQL should come first
        assert sorted_urls[0] in (
            "https://example.com/api/v1/users",
            "https://example.com/graphql",
        )
        # CSS has directory extraction so higher priority than unknown /about
        # /about is the lowest (no pattern matched)
        assert sorted_urls[-1] == "https://example.com/about"

    def test_js_files_mid_priority(self):
        urls = [
            "https://example.com/favicon.ico",        # lowest
            "https://example.com/js/app.js",          # mid-high
            "https://example.com/api/v1/users",       # highest
        ]
        sorted_urls = sort_urls_by_priority(urls)
        assert sorted_urls[0] == "https://example.com/api/v1/users"
        # JS should be above pure static
        js_idx = sorted_urls.index("https://example.com/js/app.js")
        ico_idx = sorted_urls.index("https://example.com/favicon.ico")
        assert js_idx < ico_idx


class TestPathAndQueryDetection:
    def test_has_path_parameters_numeric(self):
        assert has_path_parameters("https://example.com/api/users/12345") is True

    def test_has_path_parameters_brace(self):
        assert has_path_parameters("https://example.com/api/users/{id}") is True

    def test_has_path_parameters_colon(self):
        assert has_path_parameters("https://example.com/api/users/:id") is True

    def test_has_path_parameters_uuid(self):
        assert (
            has_path_parameters(
                "https://example.com/api/posts/550e8400-e29b-41d4-a716-446655440000"
            )
            is True
        )

    def test_no_path_parameters(self):
        assert has_path_parameters("https://example.com/about") is False

    def test_has_query_parameters(self):
        assert has_query_parameters("https://example.com/search?q=test&page=1") is True

    def test_no_query_parameters(self):
        assert has_query_parameters("https://example.com/about") is False


class TestIsEndpointWorthTesting:
    def test_api_worth_testing(self):
        assert is_endpoint_worth_testing("https://example.com/api/v1/users") is True

    def test_css_not_directly_testable(self):
        assert is_endpoint_worth_testing("https://example.com/style.css") is False

    def test_png_not_worth_testing(self):
        assert is_endpoint_worth_testing("https://example.com/img.png") is False

    def test_graphql_worth_testing(self):
        assert is_endpoint_worth_testing("https://example.com/graphql") is True

    def test_js_worth_analyzing(self):
        assert is_endpoint_worth_testing("https://example.com/js/app.js") is True

    def test_pdf_worth_checking(self):
        assert is_endpoint_worth_testing("https://example.com/docs/report.pdf") is True

    def test_search_with_params_worth_testing(self):
        assert (
            is_endpoint_worth_testing("https://example.com/search?q=test") is True
        )
