const widgetDefinitions = {
  summary: {
    label: "Summary",
    title: "Platform Summary",
    type: "Overview",
    render: renderSummaryWidget,
  },
  "open-critical": {
    label: "Open Critical Findings",
    title: "Open Critical Findings",
    type: "Findings",
    pageSize: 8,
    render: (widget, state) =>
      renderFindingsWidget(widget, {
        ...state,
        severity: "critical",
        status: "open",
      }),
  },
  "false-positive": {
    label: "False Positives",
    title: "False Positive Findings",
    type: "Findings",
    pageSize: 8,
    render: (widget, state) =>
      renderFindingsWidget(widget, {
        ...state,
        status: "false_positive",
      }),
  },
  remediated: {
    label: "Remediated Findings",
    title: "Remediated Findings",
    type: "Findings",
    pageSize: 8,
    render: (widget, state) =>
      renderFindingsWidget(widget, {
        ...state,
        status: "remediated",
      }),
  },
  "recent-events": {
    label: "Recent Automation Events",
    title: "Recent Automation Events",
    type: "Automations",
    pageSize: 8,
    render: renderEventsWidget,
  },
  "repo-priority": {
    label: "Repository P1 Findings",
    title: "Repository P1 Findings",
    type: "Findings",
    pageSize: 8,
    render: (widget, state) =>
      renderFindingsWidget(widget, {
        ...state,
        priority: "P1",
      }),
  },
};

const widgetGrid = document.querySelector("#widget-grid");
const widgetTemplate = document.querySelector("#widget-template");
const widgetSelect = document.querySelector("#widget-select");
const addWidgetButton = document.querySelector("#add-widget");
const refreshAllButton = document.querySelector("#refresh-all");
const runAutomationsButton = document.querySelector("#run-automations");
const repositoryFilter = document.querySelector("#repository-filter");
const statusFilter = document.querySelector("#status-filter");
const severityFilter = document.querySelector("#severity-filter");
const flashMessage = document.querySelector("#flash-message");

const STORAGE_KEYS = {
  widgets: "threatlens.dashboard.widgets",
  filters: "threatlens.dashboard.filters",
};

const widgetState = new Map();
let activeRefreshId = 0;
let isRefreshing = false;
let isRunningAutomations = false;

function buildQuery(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value) {
      search.set(key, value);
    }
  });
  const query = search.toString();
  return query ? `?${query}` : "";
}

async function apiFetch(path, options = {}) {
  const response = await fetch(path, options);
  const contentType = response.headers.get("content-type") || "";
  let payload = null;

  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else {
    payload = await response.text();
  }

  if (!response.ok) {
    const detail = payload?.detail || payload || `Request failed with status ${response.status}`;
    throw new Error(detail);
  }

  return payload;
}

function showFlash(message, type = "success") {
  flashMessage.textContent = message;
  flashMessage.className = `flash-message ${type}`;
}

function clearFlash() {
  flashMessage.textContent = "";
  flashMessage.className = "flash-message hidden";
}

function currentFilters() {
  return {
    repository: repositoryFilter.value,
    status: statusFilter.value,
    severity: severityFilter.value,
  };
}

function persistWidgets() {
  localStorage.setItem(STORAGE_KEYS.widgets, JSON.stringify([...widgetState.keys()]));
}

function persistFilters() {
  localStorage.setItem(STORAGE_KEYS.filters, JSON.stringify(currentFilters()));
}

function setBusyState(button, busy, busyLabel, idleLabel) {
  button.disabled = busy;
  button.textContent = busy ? busyLabel : idleLabel;
}

function updateAddWidgetButtonState() {
  const selectedWidget = widgetSelect.value;
  const alreadyAdded = widgetState.has(selectedWidget);
  addWidgetButton.disabled = alreadyAdded;
  addWidgetButton.textContent = alreadyAdded ? "Widget Added" : "Add Widget";
}

function restoreFilters() {
  try {
    const savedFilters = JSON.parse(localStorage.getItem(STORAGE_KEYS.filters) || "{}");
    statusFilter.value = savedFilters.status || "";
    severityFilter.value = savedFilters.severity || "";
  } catch (error) {
    clearFlash();
  }
}

function createWidget(widgetKey) {
  const definition = widgetDefinitions[widgetKey];
  if (!definition || widgetState.has(widgetKey)) {
    updateAddWidgetButtonState();
    return;
  }

  const fragment = widgetTemplate.content.cloneNode(true);
  const title = fragment.querySelector(".widget-title");
  const type = fragment.querySelector(".widget-type");
  const removeButton = fragment.querySelector(".widget-remove");

  title.textContent = definition.title;
  type.textContent = definition.type;

  widgetGrid.appendChild(fragment);
  const insertedCard = widgetGrid.lastElementChild;
  const widget = {
    key: widgetKey,
    card: insertedCard,
    body: insertedCard.querySelector(".widget-body"),
    page: 1,
    pageSize: definition.pageSize || 8,
  };

  removeButton.addEventListener("click", () => {
    widgetState.delete(widgetKey);
    insertedCard.remove();
    persistWidgets();
    updateAddWidgetButtonState();
  });

  widgetState.set(widgetKey, widget);
  persistWidgets();
  updateAddWidgetButtonState();
  refreshWidget(widget);
}

async function refreshWidget(widget) {
  const definition = widgetDefinitions[widget.key];
  widget.body.innerHTML = `<div class="empty-state">Loading ${definition.label.toLowerCase()}...</div>`;

  try {
    await definition.render(widget, currentFilters());
  } catch (error) {
    widget.body.innerHTML = `<div class="empty-state">Failed to load widget: ${error.message}</div>`;
  }
}

async function refreshAllWidgets() {
  const refreshId = ++activeRefreshId;
  isRefreshing = true;
  setBusyState(refreshAllButton, true, "Refreshing...", "Refresh Data");

  try {
    await populateRepositoryFilter();

    if (refreshId !== activeRefreshId) {
      return;
    }

    await Promise.all([...widgetState.values()].map(refreshWidget));
  } finally {
    if (refreshId === activeRefreshId) {
      isRefreshing = false;
      setBusyState(refreshAllButton, false, "Refreshing...", "Refresh Data");
    }
  }
}

async function populateRepositoryFilter() {
  const vulnerabilities = await apiFetch("/vulnerabilities");
  const repositories = [...new Set(vulnerabilities.map((item) => item.repository))].sort();
  const selected = repositoryFilter.value || loadSavedRepositoryFilter();

  repositoryFilter.innerHTML = `<option value="">All repositories</option>`;
  repositories.forEach((repository) => {
    const option = document.createElement("option");
    option.value = repository;
    option.textContent = repository;
    repositoryFilter.appendChild(option);
  });

  repositoryFilter.value = repositories.includes(selected) ? selected : "";
  persistFilters();
}

function loadSavedRepositoryFilter() {
  try {
    const savedFilters = JSON.parse(localStorage.getItem(STORAGE_KEYS.filters) || "{}");
    return savedFilters.repository || "";
  } catch (error) {
    return "";
  }
}

async function renderSummaryWidget(widget, filters) {
  const { body } = widget;
  const summary = await apiFetch("/summary");
  const openCritical = await apiFetch(
    `/vulnerabilities${buildQuery({ ...filters, severity: "critical", status: "open" })}`
  );
  const metrics = [
    ["Total Findings", summary.total_vulnerabilities],
    ["Open Findings", summary.open_vulnerabilities],
    ["Open Critical", openCritical.length],
    ["P1 Findings", summary.by_priority.P1 || 0],
  ];

  body.innerHTML = `
    <div class="metric-grid">
      ${metrics
        .map(
          ([label, value]) => `
            <div class="metric">
              <div class="metric-label">${label}</div>
              <div class="metric-value">${value}</div>
            </div>`
        )
        .join("")}
    </div>
    <div class="metric-grid">
      <div class="metric">
        <div class="metric-label">Severity Breakdown</div>
        <div class="metric-value">${formatBreakdown(summary.by_severity)}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Priority Breakdown</div>
        <div class="metric-value">${formatBreakdown(summary.by_priority)}</div>
      </div>
    </div>
  `;
}

function paginateItems(items, page, pageSize) {
  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safePage = Math.min(Math.max(page, 1), totalPages);
  const startIndex = totalItems === 0 ? 0 : (safePage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);

  return {
    pageItems: items.slice(startIndex, endIndex),
    safePage,
    totalPages,
    totalItems,
    startIndex,
    endIndex,
  };
}

function renderPager(widget, totalItems, startIndex, endIndex, totalPages) {
  if (!totalItems) {
    return "";
  }

  return `
    <div class="widget-footer">
      <p class="widget-meta">Showing ${startIndex + 1}-${endIndex} of ${totalItems}</p>
      <div class="pager">
        <button class="pager-button" data-action="prev" ${widget.page <= 1 ? "disabled" : ""}>Previous</button>
        <span class="pager-status">Page ${widget.page} of ${totalPages}</span>
        <button class="pager-button" data-action="next" ${widget.page >= totalPages ? "disabled" : ""}>Next</button>
      </div>
    </div>
  `;
}

function attachPagerHandlers(widget, totalPages) {
  const previousButton = widget.body.querySelector('[data-action="prev"]');
  const nextButton = widget.body.querySelector('[data-action="next"]');

  if (previousButton) {
    previousButton.addEventListener("click", () => {
      if (widget.page > 1) {
        widget.page -= 1;
        refreshWidget(widget);
      }
    });
  }

  if (nextButton) {
    nextButton.addEventListener("click", () => {
      if (widget.page < totalPages) {
        widget.page += 1;
        refreshWidget(widget);
      }
    });
  }
}

async function renderFindingsWidget(widget, overrides) {
  const query = buildQuery(overrides);
  const vulnerabilities = await apiFetch(`/vulnerabilities${query}`);
  const { pageItems, safePage, totalPages, totalItems, startIndex, endIndex } = paginateItems(
    vulnerabilities,
    widget.page,
    widget.pageSize
  );
  widget.page = safePage;

  if (!pageItems.length) {
    widget.body.innerHTML = `<div class="empty-state">No findings match the current widget and filter selection.</div>`;
    return;
  }

  widget.body.innerHTML = `
    <table class="list-table">
      <thead>
        <tr>
          <th>Package</th>
          <th>Severity</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${pageItems
          .map(
            (item) => `
              <tr>
                <td>
                  <strong>${item.package_name}</strong><br />
                  <span>${item.repository}</span>
                </td>
                <td>${item.severity.toUpperCase()} / ${item.priority}</td>
                <td><span class="status-pill ${item.status}">${formatStatus(item.status)}</span></td>
              </tr>`
          )
          .join("")}
      </tbody>
    </table>
    ${renderPager(widget, totalItems, startIndex, endIndex, totalPages)}
  `;

  attachPagerHandlers(widget, totalPages);
}

async function renderEventsWidget(widget) {
  const events = await apiFetch("/automation-events");
  const { pageItems, safePage, totalPages, totalItems, startIndex, endIndex } = paginateItems(
    events,
    widget.page,
    widget.pageSize
  );
  widget.page = safePage;

  if (!pageItems.length) {
    widget.body.innerHTML = `<div class="empty-state">No automation events logged yet.</div>`;
    return;
  }

  widget.body.innerHTML = `
    <table class="list-table">
      <thead>
        <tr>
          <th>Action</th>
          <th>Status</th>
          <th>Destination</th>
        </tr>
      </thead>
      <tbody>
        ${pageItems
          .map(
            (event) => `
              <tr>
                <td>
                  <strong>${event.action_type}</strong><br />
                  <span>Vulnerability #${event.vulnerability_id}</span>
                </td>
                <td><span class="status-pill ${event.status}">${event.status}</span></td>
                <td>${event.destination}</td>
              </tr>`
          )
          .join("")}
      </tbody>
    </table>
    ${renderPager(widget, totalItems, startIndex, endIndex, totalPages)}
  `;

  attachPagerHandlers(widget, totalPages);
}

function formatBreakdown(values) {
  const entries = Object.entries(values || {});
  if (!entries.length) {
    return "No data";
  }

  return entries.map(([key, value]) => `${key}: ${value}`).join(" | ");
}

function formatStatus(status) {
  return status.replaceAll("_", " ");
}

function restoreWidgets() {
  let widgets = [];

  try {
    widgets = JSON.parse(localStorage.getItem(STORAGE_KEYS.widgets) || "[]");
  } catch (error) {
    widgets = [];
  }

  const validWidgets = widgets.filter((widgetKey) => widgetDefinitions[widgetKey]);
  const initialWidgets = validWidgets.length ? validWidgets : ["summary", "open-critical", "recent-events"];
  initialWidgets.forEach(createWidget);
}

addWidgetButton.addEventListener("click", () => {
  createWidget(widgetSelect.value);
});

widgetSelect.addEventListener("change", updateAddWidgetButtonState);

refreshAllButton.addEventListener("click", async () => {
  try {
    clearFlash();
    await refreshAllWidgets();
    showFlash("Dashboard refreshed.", "success");
  } catch (error) {
    showFlash(error.message, "error");
  }
});

runAutomationsButton.addEventListener("click", async () => {
  if (isRunningAutomations || isRefreshing) {
    return;
  }

  isRunningAutomations = true;
  setBusyState(runAutomationsButton, true, "Running...", "Run Automations");

  try {
    clearFlash();
    const result = await apiFetch("/automations/run", { method: "POST" });
    await refreshAllWidgets();
    showFlash(
      `Automations run complete. Created ${result.events_created} events and skipped ${result.skipped_existing}.`,
      "success"
    );
  } catch (error) {
    showFlash(error.message, "error");
  } finally {
    isRunningAutomations = false;
    setBusyState(runAutomationsButton, false, "Running...", "Run Automations");
  }
});

[repositoryFilter, statusFilter, severityFilter].forEach((element) => {
  element.addEventListener("change", () => {
    persistFilters();
    widgetState.forEach((widget) => {
      widget.page = 1;
    });
    refreshAllWidgets().catch((error) => showFlash(error.message, "error"));
  });
});

restoreFilters();
restoreWidgets();
updateAddWidgetButtonState();
refreshAllWidgets().catch((error) => showFlash(error.message, "error"));
