const base = process.env.DEMO_URL ?? "http://localhost:8787";

const response = await fetch(`${base}/api/submit`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "user-agent": process.env.BOT_UA ?? "python-requests/2.32.3",
  },
  body: JSON.stringify({
    form: {
      name: "Script Bot",
      email: "bot@scraper.example",
      company: "Scraper Co",
      message: "Posted straight to the API without loading the page.",
    },
  }),
});

console.log(response.status, JSON.stringify(await response.json(), null, 2));
