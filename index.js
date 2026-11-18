import "dotenv/config";
import { connectToMongoDB } from "./src/db.js";
import { createApp } from "./src/app.js";

const port = process.env.PORT || 5000;

await connectToMongoDB();

const app = createApp();

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
