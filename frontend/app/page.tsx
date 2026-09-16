import { ClaimDemo } from "@/components/landing/ClaimDemo";
import { ClosingCta, LandingFooter } from "@/components/landing/Closing";
import { Hero } from "@/components/landing/Hero";
import { HowItWorks } from "@/components/landing/HowItWorks";
import { LandingHeader } from "@/components/landing/LandingHeader";
import { ProductPreview } from "@/components/landing/ProductPreview";

export default function Home() {
  return (
    <div className="flex flex-1 flex-col">
      <LandingHeader />
      <main className="flex flex-1 flex-col">
        <Hero />
        <ClaimDemo />
        <HowItWorks />
        <ProductPreview />
        <ClosingCta />
      </main>
      <LandingFooter />
    </div>
  );
}
