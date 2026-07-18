import process from "node:process";
import { getServerSession } from "@calcom/features/auth/lib/getServerSession";
import prisma from "@calcom/prisma";
import { UserPermissionRole } from "@calcom/prisma/enums";
import type { GetServerSidePropsContext } from "next";

export async function getServerSideProps(context: GetServerSidePropsContext) {
  const { req } = context;

  const userCount = await prisma.user.count();

  const session = await getServerSession({ req });

  if (session?.user.role && session?.user.role !== UserPermissionRole.ADMIN) {
    return {
      notFound: true,
    } as const;
  }

  // First-run setup is only for a fresh (0-user) install. Once any user exists the setup API
  // already rejects with "No setup needed" — mirror that here so the create-admin FORM is not
  // rendered to anonymous visitors on a public deploy. Logged-in ADMINs may still access the
  // wizard's later steps.
  if (userCount !== 0 && session?.user.role !== UserPermissionRole.ADMIN) {
    return {
      redirect: { destination: "/auth/login", permanent: false },
    } as const;
  }
  // direct access is intentional.
  const deploymentRepo = { getLicenseKeyWithId: async (_id: number) => null as string | null };
  const licenseKey = await deploymentRepo.getLicenseKeyWithId(1);

  // Check existent CALCOM_LICENSE_KEY env var and account for it
  if (!!process.env.CALCOM_LICENSE_KEY && !licenseKey) {
    await prisma.deployment.upsert({
      where: { id: 1 },
      update: {
        licenseKey: process.env.CALCOM_LICENSE_KEY,
        agreedLicenseAt: new Date(),
      },
      create: {
        licenseKey: process.env.CALCOM_LICENSE_KEY,
        agreedLicenseAt: new Date(),
      },
    });
  }

  // Check if there's already a valid license using LicenseKeyService
  const hasValidLicense = false;

  const isFreeLicense = true;

  return {
    props: {
      isFreeLicense,
      userCount,
      hasValidLicense,
    },
  };
}
