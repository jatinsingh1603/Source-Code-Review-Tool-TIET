import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { Button, EmptyState } from "@/components/ui";

export default function NotFoundPage() {
  return (
    <EmptyState
      icon={<Compass className="h-6 w-6" aria-hidden />}
      title="Page not found"
      description="The page you asked for does not exist or has moved."
      action={
        <Link to="/">
          <Button variant="outline">Back to overview</Button>
        </Link>
      }
    />
  );
}
