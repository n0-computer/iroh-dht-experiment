import init, { run_demo } from "./wasm/iroh_dht_experiment.js"

const output = document.querySelector("#output")
const button = document.querySelector("#run")

button.onclick = async () => {
	button.disabled = true
	output.textContent = "Loading WebAssembly...\n"
	try {
		await init()
		const log = message => {
			const line = `[${new Date().toISOString()}] ${message}`
			output.textContent += `${line}\n`
			console.log(line)
		}
		output.textContent = "Starting 16 in-page endpoints.\n"
		const result = await run_demo(log)
		output.textContent += `[${new Date().toISOString()}] ${result}\n`
	} catch (error) {
		output.textContent = error.stack ?? String(error)
		button.disabled = false
	}
}
