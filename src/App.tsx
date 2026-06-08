import { useQuery } from "@tanstack/react-query";
import { tauriInvoke } from "@/lib/ipc";
import { Button } from "@/components/ui/button";

function App() {
  const { data: platform, isLoading } = useQuery({
    queryKey: ["app", "platform"],
    queryFn: () => tauriInvoke<string>("app_platform"),
  });

  return (
    <main className="p-8 space-y-4">
      <h1 className="text-2xl font-semibold">SSHelter</h1>
      <p className="text-muted-foreground">
        platform: {isLoading ? "…" : platform}
      </p>
      <Button>It works</Button>
    </main>
  );
}

export default App;
